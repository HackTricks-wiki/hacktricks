# Active Directory कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवलोकन

**Active Directory** एक मौलिक तकनीक के रूप में काम करता है, जो **नेटवर्क व्यवस्थापकों** को नेटवर्क के भीतर **डोमेन**, **यूज़र्स**, और **ऑब्जेक्ट्स** को प्रभावी ढंग से बनाना और प्रबंधित करना सक्षम बनाता है। इसे स्केल करने के लिए डिजाइन किया गया है, जिससे बड़ी संख्या में उपयोगकर्ताओं को प्रबंधनीय **ग्रुप्स** और **सबग्रुप्स** में व्यवस्थित किया जा सकता है और विभिन्न स्तरों पर **access rights** नियंत्रित किए जा सकते हैं।

**Active Directory** की संरचना तीन प्राथमिक परतों से मिलकर बनती है: **domains**, **trees**, और **forests**। एक **domain** ऑब्जेक्ट्स का संग्रह होता है, जैसे **users** या **devices**, जो एक सामान्य database साझा करते हैं। **Trees** ऐसे domains के समूह होते हैं जो साझा संरचना द्वारा जुड़े होते हैं, और एक **forest** कई trees का संग्रह होता है, जो आपस में **trust relationships** के माध्यम से जुड़े होते हैं और संगठनात्मक संरचना की सबसे ऊपरी परत बनाते हैं। प्रत्येक स्तर पर विशिष्ट **access** और **communication rights** निर्दिष्ट किए जा सकते हैं।

Active Directory के महत्वपूर्ण कॉन्सेप्ट्स में शामिल हैं:

1. **Directory** – Active Directory ऑब्जेक्ट्स से संबंधित सभी जानकारी यहाँ संग्रहित रहती है।
2. **Object** – डायरेक्टरी के भीतर की संस्थाएँ, जिनमें **users**, **groups**, या **shared folders** शामिल हैं।
3. **Domain** – डायरेक्टरी ऑब्जेक्ट्स के लिए एक कंटेनर; एक **forest** के भीतर कई डोमेन्स हो सकते हैं, और प्रत्येक का अपना ऑब्जेक्ट संग्रह होता है।
4. **Tree** – ऐसे डोमेन्स का समूह जो एक साझा root domain साझा करते हैं।
5. **Forest** – Active Directory में संगठनात्मक संरचना का शीर्ष स्तर, जिसमें कई trees होते हैं और उनके बीच **trust relationships** होते हैं।

**Active Directory Domain Services (AD DS)** कई सेवाओं का समुच्चय है जो नेटवर्क के केंद्रीकृत प्रबंधन और संचार के लिए महत्वपूर्ण हैं। इनमें शामिल हैं:

1. **Domain Services** – डेटा स्टोरेज को केंद्रीकृत करता है और **users** और **domains** के बीच इंटरैक्शन का प्रबंधन करता है, जिसमें **authentication** और **search** कार्यक्षमताएँ शामिल हैं।
2. **Certificate Services** – सुरक्षित **digital certificates** के निर्माण, वितरण और प्रबंधन की देखरेख करता है।
3. **Lightweight Directory Services** – **LDAP protocol** के माध्यम से डायरेक्टरी-सक्षम अनुप्रयोगों का समर्थन करता है।
4. **Directory Federation Services** – कई वेब अनुप्रयोगों में एकल सत्र में उपयोगकर्ताओं को प्रमाणीकृत करने के लिए **single-sign-on** क्षमताएँ प्रदान करता है।
5. **Rights Management** – कॉपीराइट सामग्री की अनधिकृत वितरण और उपयोग को नियंत्रित कर उसकी रक्षा में सहायता करता है।
6. **DNS Service** – **domain names** के समाधान के लिए महत्वपूर्ण है।

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## चीट शीट

त्वरित दृष्टि के लिए आप [https://wadcoms.github.io/](https://wadcoms.github.io) देख सकते हैं जहाँ से यह पता चलता है कि AD को enumerate/exploit करने के लिए कौन-कौन से कमांड चलाए जा सकते हैं।

> [!WARNING]
> Kerberos संचार क्रियाएँ करने के लिए पूर्ण योग्यताप्राप्त नाम (FQDN) की आवश्यकता होती है। यदि आप किसी मशीन को IP पते से एक्सेस करने की कोशिश करते हैं, तो यह NTLM का उपयोग करेगा और kerberos का नहीं करेगा।

## Recon Active Directory (No creds/sessions)

यदि आपके पास केवल AD environment तक पहुँच है लेकिन आपके पास कोई credentials/sessions नहीं हैं तो आप कर सकते हैं:

- **Pentest the network:**
- नेटवर्क स्कैन करें, मशीनें और ओपन पोर्ट ढूँढें और कोशिश करें कि उन पर मौजूद कमजोरियों का **exploit** करें या उनसे **credentials extract** करें (उदाहरण के लिए, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS को enumerate करने से डोमेन में महत्वपूर्ण सर्वरों के बारे में जानकारी मिल सकती है जैसे वेब, प्रिंटर, shares, vpn, media, आदि।
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- और अधिक जानकारी के लिए General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) देखें कि यह कैसे किया जाता है।
- **Check for null and Guest access on smb services** (यह आधुनिक Windows वर्जन्स पर काम नहीं करेगा):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB सर्वर को enumerate करने का एक विस्तृत गाइड यहाँ पाया जा सकता है:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP को enumerate करने के लिए एक विस्तृत गाइड यहाँ है (विशेष रूप से anonymous access पर ध्यान दें):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder के साथ सेवाओं का impersonate करके credentials इकट्ठा करें: [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) के माध्यम से होस्ट तक पहुँच प्राप्त करें
- **fake UPnP services** के प्रदर्शन से credentials इकट्ठा करें जैसे evil-S [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- आंतरिक दस्तावेज़ों, सोशल मीडिया, सेवाओं (मुख्यतः वेब) और सार्वजनिक रूप से उपलब्ध स्रोतों से usernames/names निकालें।
- यदि आपको कंपनी के कर्मचारियों के पूर्ण नाम मिल जाते हैं, तो आप विभिन्न AD **username conventions** आजमा सकते हैं ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/))। सबसे सामान्य conventions हैं: _NameSurname_, _Name.Surname_, _NamSur_ (प्रत्येक से 3 अक्षर), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) और [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) पेज देखें।
- **Kerbrute enum**: जब कोई **invalid username request** किया जाता है तो सर्वर **Kerberos error** कोड _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ के साथ उत्तर देगा, जिससे हम निर्धारित कर सकते हैं कि username अमान्य था। **Valid usernames** पर या तो **TGT in a AS-REP** रिस्पॉन्स मिलेगा या फिर त्रुटि _KRB5KDC_ERR_PREAUTH_REQUIRED_ होगी, जो संकेत देती है कि user को pre-authentication करने की आवश्यकता है।
- **No Authentication against MS-NRPC**: domain controllers पर MS-NRPC (Netlogon) इंटरफ़ेस के खिलाफ auth-level = 1 (No authentication) का उपयोग करना। यह विधि MS-NRPC इंटरफ़ेस को bind करने के बाद `DsrGetDcNameEx2` फ़ंक्शन को कॉल करती है ताकि बिना किसी credentials के यह जांचा जा सके कि user या computer मौजूद है या नहीं। इस प्रकार के enumeration को लागू करने वाला टूल [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) है। रिसर्च यहाँ पाई जा सकती है: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

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

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

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

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **अधिक ईमेल और नेटवर्क की बेहतर समझ**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **खोजना** कोई भी **दिलचस्प फाइलें जो AD के अंदर साझा हो रही हों**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


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

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
फिर, अब सभी hashes को memory और लोकली dump करने का समय है।\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**एक बार जब आपके पास किसी user का hash हो**, आप उसे **impersonate** कर सकते हैं।\
आपको कुछ ऐसा **tool** इस्तेमाल करना होगा जो उस **hash** का उपयोग करके **NTLM authentication** करे, **या** आप नया **sessionlogon** बना कर वह **hash** **LSASS** में **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication** किया जाए, वह **hash** उपयोग हो। अंतिम विकल्प वही है जो mimikatz करता है।\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> ध्यान दें कि यह काफी **शोरगुल** है और **LAPS** इसे **घटाएगा**।

### MSSQL Abuse & Trusted Links

यदि किसी user के पास **MSSQL instances** को **access** करने के privileges हैं, तो वह इसे MSSQL host पर **commands execute** करने (यदि यह SA के रूप में चल रहा हो), NetNTLM **hash** चुराने या यहाँ तक कि **relay attack** करने के लिए उपयोग कर सकता है.\
इसके अलावा, यदि कोई MSSQL instance किसी दूसरे MSSQL instance द्वारा trusted (database link) है और user के पास trusted database पर privileges हैं, तो वह **trust relationship का उपयोग करके दूसरे instance में भी queries execute** कर पाएगा। ये trusts chain किए जा सकते हैं और किसी बिंदु पर user को कोई misconfigured database मिल सकती है जहाँ वह commands execute कर सके।\
**Databases के बीच के links forest trusts के across भी काम करते हैं।**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

तीसरे-पक्ष के inventory और deployment suites अक्सर credentials और code execution तक शक्तिशाली रास्ते प्रदान करते हैं। देखें:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

यदि आप किसी Computer object में attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) देखते हैं और आपके पास उस computer में domain privileges हैं, तो आप उस कंप्यूटर पर लॉगिन करने वाले हर उपयोगकर्ता की memory से TGTs dump कर पाएंगे।\
यदि कोई **Domain Admin उस कंप्यूटर पर लॉगिन करता है**, तो आप उसका TGT dump कर के [Pass the Ticket](pass-the-ticket.md) का उपयोग करके उसकी impersonation कर पाएंगे।\
constrained delegation की वजह से आप यहाँ तक कि **automatically एक Print Server compromise** भी कर सकते हैं (उम्मीद है वह DC होगा)।

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

यदि किसी user या computer को "Constrained Delegation" की अनुमति है, तो वह **किसी कंप्यूटर पर कुछ services तक पहुँचने के लिए किसी भी user की impersonation** कर सकेगा।\
यदि आप इस user/computer के **hash compromise** कर लेते हैं तो आप **किसी भी user** (यहाँ तक कि domain admins भी) की impersonation करके कुछ services तक पहुँच सकते हैं।


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Remote computer के Active Directory object पर **WRITE** privilege होने से **elevated privileges** के साथ code execution प्राप्त करना संभव हो जाता है:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Compromised user के पास कुछ domain objects पर **दिलचस्प privileges** हो सकते हैं जो आपको बाद में lateral movement/privilege **escalation** करने की क्षमता देंगे।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain के अंदर किसी भी **Spool service listening** का पता लगने पर उसे **abuse** करके **नई credentials प्राप्त** की जा सकती हैं और **privileges escalate** किए जा सकते हैं।


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

यदि **अन्य users** compromised मशीन पर **access** करते हैं, तो संभव है कि उनसे **memory से credentials gather** किए जाएँ और उनके processes में **beacons inject** करके उनकी impersonation की जा सके।\
आम तौर पर users सिस्टम तक RDP के जरिए पहुँचते हैं, इसलिए यहाँ कुछ तरीक़े दिए गए हैं जो third party RDP sessions पर किए जा सकते हैं:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** domain-joined computers पर **local Administrator password** manage करने का एक सिस्टम देता है, जो इसे **randomized**, unique और बार-बार **change** करता है। ये पासवर्ड Active Directory में store होते हैं और ACLs के माध्यम से केवल authorized users को access दिया जाता है। यदि किसी के पास इन पासवर्ड्स तक पर्याप्त permissions हों, तो दूसरे कंप्यूटरों पर pivot करना संभव हो जाता है।


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Compromised मशीन से **certificates इकट्ठा करना** environment में privileges escalate करने का एक तरीका हो सकता है:


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

एक बार जब आप **Domain Admin** या उस से भी बेहतर **Enterprise Admin** privileges हासिल कर लेते हैं, तो आप **domain database**: _ntds.dit_ **dump** कर सकते हैं।

[**DCSync attack के बारे में अधिक जानकारी यहाँ मिलती है**](dcsync.md).

[**NTDS.dit चुराने के तरीके के बारे में अधिक जानकारी यहाँ मिलती है**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

पहले चर्चा की गई कुछ तकनीकों को persistence के लिए भी उपयोग किया जा सकता है।\
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

**Silver Ticket attack** एक विशिष्ट सर्विस के लिए एक वैध Ticket Granting Service (TGS) ticket बनाता है, आमतौर पर NTLM hash (उदाहरण के लिए PC account का hash) का उपयोग करके। यह तरीका service privileges तक पहुँचने के लिए उपयोग किया जाता है।


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** में attacker Active Directory में **krbtgt account** का NTLM hash हासिल कर लेता है। यह खाता विशेष है क्योंकि यह सभी **Ticket Granting Tickets (TGTs)** को sign करने के लिए प्रयोग होता है, जो AD नेटवर्क में authentication के लिए आवश्यक होते हैं।

एक बार attacker इस hash को प्राप्त कर लेता है, तो वह किसी भी खाते के लिए **TGTs** बना सकता है (Silver ticket attack जैसा)।


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

ये golden tickets की तरह होते हैं पर इन्हें इस तरह forge किया जाता है कि वे **आम golden tickets detection mechanisms** को bypass कर दें।


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**किसी account के certificates होना या उन्हें request कर पाने की क्षमता** users के account में persist रहने का एक बहुत अच्छा तरीका है (यहाँ तक कि user पासवर्ड बदल दे तो भी):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates का उपयोग domain के भीतर उच्च privileges के साथ persist करने के लिए भी किया जा सकता है:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory में **AdminSDHolder** object privileged groups (जैसे Domain Admins और Enterprise Admins) की security सुनिश्चित करने के लिए एक standard **Access Control List (ACL)** apply करता है ताकि unauthorized changes रोके जा सकें। हालांकि, इस फीचर का दुरुपयोग किया जा सकता है; यदि attacker AdminSDHolder के ACL को modify कर के किसी सामान्य user को full access दे दे, तो उस user को सभी privileged groups पर विस्तृत नियंत्रण मिल जाएगा। यह सुरक्षा उपाय, जिसे सुरक्षा के लिए रखा गया है, यदि ठीक से monitored न हो तो अनचाही access दे सकता है।

[**AdminSDHolder Group के बारे में अधिक जानकारी यहाँ।**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

हर **Domain Controller (DC)** के अंदर एक local administrator account मौजूद होता है। ऐसी मशीन पर admin rights प्राप्त करके local Administrator hash को **mimikatz** का उपयोग कर निकालना संभव है। इसके बाद कुछ registry modifications करने की आवश्यकता होती है ताकि इस password का उपयोग enable किया जा सके और local Administrator account में remote access मिल सके।


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

आप किसी user को कुछ विशेष permissions दे सकते हैं किसी specific domain objects पर ताकि वह भविष्य में privileges escalate कर सके।


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** किसी object के ऊपर मौजूद permissions को **store** करने के लिए उपयोग होते हैं। यदि आप किसी object के security descriptor में छोटी सी भी **बदलाव** कर दें, तो आप उस object पर बहुत ही दिलचस्प privileges प्राप्त कर सकते हैं बिना यह कि आपको privileged group का सदस्य होना पड़े।


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS की memory को बदलकर एक **universal password** स्थापित किया जाता है, जिससे सभी domain accounts तक पहुँच मिल जाती है।


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[यहाँ जानें कि SSP (Security Support Provider) क्या है.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप अपना **SSP** बना सकते हैं ताकि मशीन पर उपयोग किए जा रहे credentials को **clear text** में **capture** किया जा सके।


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

यह AD में एक **नया Domain Controller** register करता है और इसे उपयोग कर के निर्दिष्ट objects पर attributes (SIDHistory, SPNs...) **push** करता है बिना उन **modifications** के बारे में logs छोड़े। इसके लिए आपको DA privileges चाहिए और आप **root domain** के अंदर होने चाहिए।\
ध्यान दें कि यदि आप गलत data use करते हैं तो काफी भद्दे logs दिखाई देंगे।


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

पहले हमने चर्चा की थी कि यदि आपके पास **LAPS passwords पढ़ने की पर्याप्त permission** है तो कैसे privileges escalate किए जा सकते हैं। हालांकि, इन पासवर्ड्स का उपयोग **persistence बनाए रखने** के लिए भी किया जा सकता है।\
देखें:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft **Forest** को security boundary के रूप में देखता है। इसका मतलब यह है कि **एक ही domain का compromise पूरे Forest के compromise की ओर ले जा सकता है**।

### Basic Information

एक [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) एक security mechanism है जो एक domain के user को दूसरे domain के resources तक पहुँचने की अनुमति देता है। यह दोनों domains के authentication systems के बीच एक linkage बनाता है ताकि authentication verifications seamlessly flow कर सकें। जब domains trust set करते हैं, तो वे अपने Domain Controllers (DCs) के बीच कुछ specific **keys** exchange और retain करते हैं, जो trust की integrity के लिए महत्वपूर्ण होते हैं।

सामान्य परिदृश्य में, यदि किसी user को किसी **trusted domain** की सेवा तक पहुँच चाहिए होती है, तो उसे पहले अपने domain के DC से एक विशेष ticket जिसे **inter-realm TGT** कहा जाता है, request करनी होती है। यह TGT उस shared **key** के साथ encrypt होती है जो दोनों domains ने agree की होती है। फिर user यह TGT **trusted domain के DC** को प्रस्तुत करता है ताकि उसे service ticket (**TGS**) मिल सके। यदि trusted domain का DC inter-realm TGT को validate कर लेता है, तो वह TGS जारी करता है और user को सेवा तक पहुँच मिल जाती है।

**Steps**:

1. एक **client computer** **Domain 1** में अपनी **NTLM hash** का उपयोग करके अपने **Domain Controller (DC1)** से **Ticket Granting Ticket (TGT)** request करना शुरू करता है।
2. अगर client authenticate हो जाता है तो DC1 नया TGT जारी करता है।
3. फिर client को **Domain 2** के resources तक पहुँचने के लिए DC1 से एक **inter-realm TGT** request करनी होती है।
4. inter-realm TGT उस **trust key** से encrypt होती है जो DC1 और DC2 के बीच two-way domain trust का हिस्सा है।
5. client inter-realm TGT लेकर **Domain 2 के Domain Controller (DC2)** के पास जाता है।
6. DC2 अपनी shared trust key से inter-realm TGT verify करता है और यदि valid हो तो उस server के लिए **Ticket Granting Service (TGS)** जारी करता है जिसे client पहुँचने का प्रयास कर रहा है।
7. अंत में client यह TGS server को प्रस्तुत करता है, जो कि server के account hash से encrypt होता है, और Domain 2 में service तक पहुँच प्राप्त करता है।

### Different trusts

यह ज़रूरी है कि समझें कि **एक trust one way या two ways** हो सकता है। दो-तरफ़ा विकल्प में दोनों domains एक-दूसरे पर भरोसा करेंगे, लेकिन **one way** trust में एक domain **trusted** और दूसरा **trusting** होगा। ऐसी स्थिति में, **trusted domain से आप केवल trusting domain के अंदर मौजूद resources तक ही access कर पाएँगे**।

यदि Domain A, Domain B पर trust करता है, तो A trusting domain होगा और B trusted। इसके अलावा, **Domain A** में इसे **Outbound trust** कहा जाएगा; और **Domain B** में इसे **Inbound trust** कहा जाएगा।

**Different trusting relationships**

- **Parent-Child Trusts**: यह आमतौर पर एक ही forest के अंदर होता है, जहाँ child domain अपने parent domain के साथ स्वचालित रूप से two-way transitive trust रखता है। इसका अर्थ यह है कि authentication requests parent और child के बीच बिना बाधा के flow कर सकते हैं।
- **Cross-link Trusts**: जिन्हें "shortcut trusts" भी कहा जाता है, ये child domains के बीच स्थापित किए जाते हैं ताकि referral processes तेज़ हों। जटिल forests में authentication referrals आमतौर पर forest root तक ऊपर और फिर target domain तक नीचे यात्रा करते हैं। cross-links बनाकर यह मार्ग छोटा किया जा सकता है, जो भौगोलिक रूप से फैले वातावरण में उपयोगी है।
- **External Trusts**: ये unrelated domains के बीच स्थापित किए जाते हैं और प्रकृति में non-transitive होते हैं। Microsoft के documentation के अनुसार external trusts उन मामलों के लिए उपयोगी हैं जहाँ current forest के बाहर किसी domain के resources तक पहुँचने की आवश्यकता होती है जो forest trust से connected नहीं है। सुरक्षा को external trusts के साथ SID filtering के माध्यम से बढ़ाया जाता है।
- **Tree-root Trusts**: ये trusts forest root domain और newly added tree root के बीच स्वचालित रूप से स्थापित होते हैं। अक्सर नहीं मिलते, लेकिन tree-root trusts नए domain trees को forest में जोड़ने के लिए महत्वपूर्ण होते हैं, जिससे वे unique domain name बनाए रख सकें और two-way transitivity सुनिश्चित हो।
- **Forest Trusts**: यह प्रकार दो forest root domains के बीच एक two-way transitive trust होता है, और SID filtering सुरक्षा उपाय के रूप में लागू करता है।
- **MIT Trusts**: ये non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains के साथ स्थापित किए जाने वाले trusts हैं। MIT trusts थोड़े अधिक specialized होते हैं और उन वातावरणों के लिए होते हैं जो Windows पारिस्थितिकी तंत्र के बाहर Kerberos-based systems के साथ integration की आवश्यकता रखते हैं।

#### Other differences in **trusting relationships**

- एक trust relationship **transitive** भी हो सकती है (A trusts B, B trusts C, तो A trusts C) या **non-transitive** भी।
- एक trust relationship को **bidirectional trust** के रूप में सेट किया जा सकता है (दोनों एक-दूसरे पर भरोसा करते हैं) या **one-way trust** के रूप में (केवल एक ही दूसरे पर भरोसा करता है)।

### Attack Path

1. **Enumerate** करें trusting relationships को
2. जाँचें कि क्या कोई **security principal** (user/group/computer) के पास **other domain** के resources तक **access** है, संभवतः ACE entries या दूसरे domain के groups में होने की वजह से। **domains के बीच relationships** देखें (शायद trust इसे बनाने के लिए ही बनाई गई थी)।
1. इस मामले में kerberoast भी एक विकल्प हो सकता है।
3. उन **accounts** को **compromise** करें जो domains के बीच **pivot** कर सकती हैं।

Attackers को दूसरे domain में resources तक पहुँचने के तीन प्रमुख मैकेनिज्म के माध्यम से access मिल सकती है:

- **Local Group Membership**: Principals को machines पर local groups (जैसे किसी server पर “Administrators” group) में जोड़ा जा सकता है, जिससे उन्हें उस मशीन पर काफी control मिल जाता है।
- **Foreign Domain Group Membership**: Principals foreign domain के groups के सदस्य भी हो सकते हैं। हालांकि, इस विधि की प्रभावशीलता trust की प्रकृति और group के scope पर निर्भर करती है।
- **Access Control Lists (ACLs)**: Principals को किसी resource तक पहुँच प्रदान करने के लिए **ACL** में, विशेष रूप से **ACE** के रूप में, निर्दिष्ट किया जा सकता है। ACLs, DACLs और ACEs की कार्यप्रणाली में गहराई से जाने के इच्छुक लोगों के लिए whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” उपयोगी संसाधन है।

### Find external users/groups with permissions

आप domain में foreign security principals खोजने के लिए **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** की जाँच कर सकते हैं। ये entries **external domain/forest** के user/group होंगे।

आप इसे **Bloodhound** में या **powerview** का उपयोग करके जाँच सकते हैं:
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
> 2 **trusted keys** हैं, एक _Child --> Parent_ के लिए और दूसरी _Parent_ --> _Child_ के लिए।\
> आप वर्तमान डोमेन द्वारा उपयोग की जा रही कुंजी को निम्नलिखित के साथ देख/प्राप्त कर सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Trust का दुरुपयोग करके SID-History injection के साथ child/parent डोमेन में Enterprise admin के रूप में escalate करें:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

यह समझना कि Configuration Naming Context (NC) का कैसे exploit किया जा सकता है, बहुत महत्वपूर्ण है। Configuration NC Active Directory (AD) वातावरण में पूरे forest के configuration डेटा के लिए एक केंद्रीय रिपॉज़िटरी का काम करता है। यह डेटा forest के प्रत्येक Domain Controller (DC) पर replicate होता है, और writable DCs Configuration NC की writable copy बनाए रखते हैं। इसका exploit करने के लिए, किसी के पास **SYSTEM privileges on a DC**, वरीयता रूप से एक child DC, होना चाहिए।

**Link GPO to root DC site**

Configuration NC के Sites container में AD forest के भीतर सभी domain-joined कंप्यूटर्स की sites की जानकारी शामिल होती है। किसी भी DC पर SYSTEM privileges के साथ काम करके, attacker GPOs को root DC sites से link कर सकते हैं। यह क्रिया इन sites पर लागू नीतियों का हेरफेर करके root domain को संभावित रूप से compromise कर सकती है।

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

एक attack vector में domain के अंदर privileged gMSAs को target करना शामिल है। gMSA के पासवर्ड की गणना के लिए आवश्यक KDS Root key Configuration NC में संग्रहीत होती है। किसी भी DC पर SYSTEM privileges के साथ, KDS Root key तक पहुँच बनाकर forest भर के किसी भी gMSA के पासवर्ड की गणना की जा सकती है।

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

यह विधि धैर्य मांगती है, नए privileged AD objects के बनने का इंतजार करना। SYSTEM privileges के साथ, attacker AD Schema को संशोधित कर सकता है ताकि किसी भी user को सभी classes पर पूर्ण कंट्रोल दिया जा सके। इससे नए बनाए गए AD objects पर अनधिकृत पहुँच और नियंत्रण हो सकता है।

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability का उद्देश्य Public Key Infrastructure (PKI) objects पर नियंत्रण हासिल करना है ताकि एक certificate template बनाया जा सके जो forest के किसी भी user के रूप में authentication सक्षम करे। चूँकि PKI objects Configuration NC में स्थित होते हैं, एक writable child DC को compromise करने से ESC5 attacks को execute करना संभव हो जाता है।

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
इस परिदृश्य में **आपका डोमेन** एक बाहरी डोमेन द्वारा ट्रस्ट किया गया है जो आपको उस पर **अनिर्धारित अनुमतियाँ** देता है। आपको यह पता लगाना होगा कि **आपके डोमेन के कौन से principals को बाहरी डोमेन पर किस तरह का access है** और फिर इसे exploit करने की कोशिश करनी होगी:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### बाहरी फॉरेस्ट डोमेन - एकतरफ़ा (Outbound)
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
In this scenario **आपका डोमेन** कुछ **अधिकार** किसी **अलग डोमेन** के प्रिंसिपल को **ट्रस्ट** कर रहा है।

हालाँकि, जब एक **डोमेन को ट्रस्ट किया जाता है** ट्रस्टिंग डोमेन द्वारा, ट्रस्टेड डोमेन **एक यूजर बनाता है** जिसका **नाम पूर्वानुमेय** होता है और जिसका पासवर्ड **ट्रस्टेड पासवर्ड** के रूप में उपयोग होता है। इसका मतलब यह है कि यह संभव है कि ट्रस्टिंग डोमेन का एक यूजर एक्सेस कर सके और ट्रस्टेड डोमेन के अंदर जा कर उसे सूचीबद्ध करके अधिक अधिकार बढ़ाने की कोशिश करे:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

ट्रस्टेड डोमेन को कॉम्प्रोमाइज़ करने का एक और तरीका है [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) ढूँढना जो domain trust की **विपरीत दिशा** में बनाया गया हो (जो बहुत आम नहीं है).

ट्रस्टेड डोमेन को कॉम्प्रोमाइज़ करने का एक और तरीका यह है कि किसी मशीन पर प्रतीक्षा करना जहां एक **trusted domain का user RDP के माध्यम से लॉगिन कर सकता है**। फिर, attacker RDP session process में कोड inject कर सकता है और वहाँ से **victim के origin domain** तक पहुँच सकता है.\ Moreover, अगर **victim ने अपना हार्ड ड्राइव माउंट किया हुआ है**, तो **RDP session** प्रक्रिया से attacker हार्ड ड्राइव के **startup folder** में **backdoors** स्टोर कर सकता है। इस तकनीक को **RDPInception** कहा जाता है।


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### डोमेन ट्रस्ट दुरुपयोग से रक्षा

### **SID Filtering:**

- SID history attribute का उपयोग करके forest trusts के पार होने वाले अटैक्स के जोखिम को SID Filtering द्वारा कम किया जाता है, जिसे सभी inter-forest trusts पर डिफ़ॉल्ट रूप से सक्रिय किया जाता है। यह इस धारणा पर आधारित है कि intra-forest trusts सुरक्षित हैं, Microsoft के दृष्टिकोण के अनुसार forest को domain की तुलना में सुरक्षा सीमा माना जाता है।
- हालाँकि, एक समस्या यह है कि SID filtering applications और user access को बाधित कर सकता है, जिससे इसे कभी-कभी निष्क्रिय कर दिया जाता है।

### **Selective Authentication:**

- inter-forest trusts के लिए, Selective Authentication लागू करने से सुनिश्चित होता है कि दोनों forests के users स्वचालित रूप से authenticated न हों। इसके बजाय, users को trusting domain या forest के भीतर domains और servers तक पहुँचने के लिए स्पष्ट permissions की आवश्यकता होती है।
- यह ध्यान रखना महत्वपूर्ण है कि ये उपाय writable Configuration Naming Context (NC) के शोषण या trust account पर होने वाले अटैक्स से सुरक्षा प्रदान नहीं करते।

[**domain trusts के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## कुछ सामान्य सुरक्षा उपाय

[**यहाँ क्रेडेंशियल्स की सुरक्षा कैसे करें के बारे में और जानें।**](../stealing-credentials/credentials-protections.md)

### **क्रेडेंशियल सुरक्षा के लिए रक्षात्मक उपाय**

- **Domain Admins Restrictions**: सलाह दी जाती है कि Domain Admins को केवल Domain Controllers पर लॉगिन करने की अनुमति दी जाए और अन्य hosts पर उनका उपयोग टाला जाए।
- **Service Account Privileges**: सुरक्षा बनाए रखने के लिए सेवाओं को Domain Admin (DA) privileges के साथ नहीं चलाना चाहिए।
- **Temporal Privilege Limitation**: DA privileges वाले कार्यों के लिए उनकी अवधि सीमित रखनी चाहिए। इसे निम्न कमांड के द्वारा हासिल किया जा सकता है: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Deception Techniques लागू करना**

- Deception लागू करने में जाल लगाना शामिल है, जैसे decoy users या computers बनाना, जिनमें ऐसे फीचर हों जैसे passwords जो expire न हों या जिन्हें Trusted for Delegation के रूप में चिह्नित किया गया हो। एक विस्तृत तरीका specific rights वाले users बनाना या उन्हें high privilege groups में जोड़ना शामिल है।
- एक व्यावहारिक उदाहरण में निम्न टूल का उपयोग शामिल है: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques deploy करने के बारे में अधिक जानकारी [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) पर मिल सकती है।

### **Deception की पहचान**

- **For User Objects**: संदिग्ध संकेतों में atypical ObjectSID, कम logons, creation dates, और low bad password counts शामिल हैं।
- **General Indicators**: संभावित decoy objects के attributes की वास्तविक objects से तुलना करने पर असंगतियाँ पता चल सकती हैं। [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) जैसे tools ऐसी deceptions पहचानने में मदद कर सकते हैं।

### **Detection Systems को बायपास करना**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection से बचने के लिए Domain Controllers पर session enumeration से बचना।
- **Ticket Impersonation**: ticket creation के लिए **aes** keys का उपयोग करना detection से बचने में मदद करता क्योंकि यह NTLM पर डाउनग्रेड नहीं करता।
- **DCSync Attacks**: ATA detection से बचने के लिए non-Domain Controller से execute करना सुझाया जाता है, क्योंकि सीधे Domain Controller से execute करने पर alerts ट्रिगर होंगे।

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
