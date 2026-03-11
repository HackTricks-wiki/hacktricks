# Mbinu ya Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa Msingi

**Active Directory** inafanya kazi kama teknolojia ya msingi, ikimrahisishia **wasimamizi wa mtandao** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa kwa ajili ya kuhimili ukuaji, ikiwalenga kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** zinazoweza kudhibitiwa, huku ikidhibiti **access rights** kwa ngazi mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** ni mkusanyiko wa objects, kama **users** au **devices**, zinazoshiriki hifadhidata moja. **Trees** ni vikundi vya domain hivi vinavyohusishwa kwa muundo wenye asili moja, na **forest** ni mkusanyiko wa miti kadhaa inayounganishwa kupitia **trust relationships**, ikitengeneza tabaka la juu kabisa la muundo wa shirika. Haki maalum za **access** na **communication** zinaweza kutolewa katika kila moja ya ngazi hizi.

Madhumuni muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Inahifadhi taarifa zote zinazohusu Active Directory objects.
2. **Object** – Inamaanisha vitu ndani ya directory, ikijumuisha **users**, **groups**, au **shared folders**.
3. **Domain** – Hutoa chombo cha kuhifadhi objects za directory, na inawezekana kwa domains nyingi kuishi ndani ya **forest**, kila moja ikiweka mkusanyiko wake wa objects.
4. **Tree** – Ufunguo wa domains zinazoshirikiana root domain moja.
5. **Forest** – Ngazi ya juu kabisa ya muundo wa shirika katika Active Directory, inayojumuisha miti kadhaa zenye **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa katikati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inaleta utunzaji wa data kwa kitu kimoja na kusimamia mwingiliano kati ya **users** na **domains**, ikiwa ni pamoja na **authentication** na uwezo wa **search**.
2. **Certificate Services** – Inasimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Inasaidia programu zilizo na directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** ili kuthibitisha watumiaji kwenye tovuti nyingi za wavuti kwa kipindi kimoja.
5. **Rights Management** – Inasaidia kulinda mali za hakimiliki kwa kudhibiti usambazaji na matumizi yasiyoidhinishwa.
6. **DNS Service** – Muhimu kwa kutatua **domain names**.

Kwa maelezo zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya kushambulia AD unahitaji kuelewa vizuri mchakato wa **Kerberos authentication**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Muhtasari wa Mbinu (Cheat Sheet)

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muonekano wa haraka wa amri unaweza kuzitekeleza ku-orodhesha/ku-exploit AD.

> [!WARNING]
> Kerberos communication **inahitaji full qualifid name (FQDN)** kufanikisha vitendo. Ukijaribu kufikia mashine kwa kutumia anwani ya IP, **itaitumia NTLM na si kerberos**.

## Uchunguzi wa Active Directory (Hakuna kredenshiali/vikao)

Ikiwa una upatikanaji wa mazingira ya AD lakini huna kredenshiali/vikao unaweza:

- **Pentest the network:**
- Skana mtandao, tafuta mashine na port zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwazo (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Kurodhesha DNS kunaweza kutoa taarifa kuhusu server muhimu ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Tazama mwongozo wa jumla wa [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kwa maelezo zaidi kuhusu jinsi ya kufanya hili.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye toleo za kisasa za Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina juu ya jinsi ya ku-enumerate SMB server unaweza kupatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina juu ya jinsi ya ku-enumerate LDAP unaweza kupatikana hapa (lipa **umakini maalum kwa anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa **impersonating services with Responder** ({{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza kuwa na uwezo wa **kupata** baadhi ya challenge **hashes** za kuvunja kwa kufanya **poisoning** ya baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa ku-enumerate Active Directory utapata **barua pepe zaidi na uelewa mzuri wa network**. Unaweza kuweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa AD env.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi state ya AD recon kwa kila engagement: `workspace create <name>` hutoa per-protocol SQLite DBs chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha view kwa `proto smb|mssql|winrm` na orodha ya secrets zilizokusanywa kwa `creds`. Futa kwa mkono data nyeti ukimaliza: `rm -rf ~/.nxc/workspaces/<name>`.
- Ugunduzi wa subnet haraka kwa kutumia **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Members wanaoonyesha `(signing:False)` ni **relay-prone**, wakati DCs mara nyingi zinahitaji signing.
- Generate **hostnames in /etc/hosts** moja kwa moja kutoka kwa output ya NetExec ili kurahisisha kulenga:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wakati **SMB relay to the DC is blocked** kwa sababu ya signing, bado chunguza postura ya **LDAP**: `netexec ldap <dc>` inaonyesha `(signing:None)` / weak channel binding. DC ambayo SMB signing required lakini LDAP signing disabled inabaki kuwa target inayofaa ya **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Client-side printer credential leaks → uthibitishaji wa wingi wa credentials za domain

- Printer/web UIs wakati mwingine **huweka masked admin passwords ndani ya HTML**. Kuangalia source/devtools kunaweza kufichua cleartext (kwa mfano, `<input value="<password>">`), ikiruhusu Basic-auth access kwa repositories za scan/print.
- Retrieved print jobs zinaweza kuwa na **plaintext onboarding docs** zenye per-user passwords. Weka jozi zikilingana wakati wa kujaribu:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Ikiwa unaweza **access other PCs or shares** kwa **null or guest user** unaweza **place files** (kama SCF file) ambazo, zikifunguliwa kwa namna yoyote, zitatisha **NTLM authentication against you** ili uweze **steal** **NTLM challenge** kwa ajili ya kuzi-crack:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** inachukulia kila NT hash uliyonayo tayari kama candidate password kwa formats nyingine, ambazo key material yake hutokana moja kwa moja na NT hash. Badala ya brute-forcing passphrases ndefu kwenye Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unalisha NT hashes kwenye Hashcat’s NT-candidate modes na kuruhusu kuthibitisha password reuse bila kujua plaintext. Hii ni mbinu yenye nguvu hasa baada ya kufanikiwa domain compromise ambapo unaweza kuvuna maelfu ya NT hashes za sasa na za zamani.

Tumia shucking wakati:

- Una NT corpus kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu reuse katika domains/forests nyingine.
- Umepata RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha reuse kwa haraka kwa passphrases ndefu zisizoweza ku-crack na mara moja ku-pivot kwa Pass-the-Hash.

Mbinu hii **haitafanya kazi** dhidi ya encryption types ambazo keys hazitoki kwenye NT hash (mf. Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES-only, lazima utumie regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` na history ili kupata set kubwa zaidi ya NT hashes (na values zao za zamani):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries zinapanuka sana candidate pool kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 za awali kwa akaunti moja. Kwa njia zaidi za kuvuna NTDS secrets ona:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa SAM/SECURITY ya eneo na cached domain logons (DCC/DCC2). Futa nakala rudufu na uongeze hashes hizo kwenye orodha ile ile ya `nt_candidates.txt`.
- **Track metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex tu). Matching hashes zitakuambia mara moja ni principal gani anatumia tena password wakati Hashcat itapoonyesha candidate iliyoshinda.
- Chagua candidates kutoka forest ile ile au trusted forest; hilo linaongeza nafasi ya overlap wakati wa shucking.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Zima rule engines (hakuna `-r`, hakuna hybrid modes) kwa sababu mangling huharibika candidate key material.
- Modes hizi si za kasi zaidi kwa asili, lakini keyspace ya NTLM (~30,000 MH/s on an M3 Max) ni ~100× haraka kuliko Kerberos RC4 (~300 MH/s). Kuikagua list iliyopangwa ya NT ni nafuu zaidi kuliko kuchunguza password space yote kwenye format polepole.
- Kila mara tumia **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zililetwa hivi karibuni.
- Kwa sasa hakuna NT mode kwa AS-REQ Pre-Auth, na AES etypes (19600/19700) zinahitaji plaintext password kwa sababu keys zao zinatokana via PBKDF2 kutoka kwa UTF-16LE passwords, si raw NT hashes.

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

Hashcat inatokana na kila NT candidate kupata RC4 key na kuthibitisha `$krb5tgs$23$...` blob. Match inathibitisha kuwa service account inatumia moja ya NT hashes ulizonazo.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Unaweza pia kurecover plaintext baadaye kwa `hashcat -m 1000 <matched_hash> wordlists/` ikiwa inahitajika.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons kutoka workstation iliyokomomolewa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Nakili mstari wa DCC2 wa domain user inayovutia ndani ya `dcc2_highpriv.txt` na uishuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Match iliyofanikiwa inaonyesha NT hash ambayo tayari ilijulikana kwenye orodha yako, ikithibitisha kuwa cached user analingana password. Tumia moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au brute-force kwa fast NTLM mode ili kupata string.

Workflow ile ile inatumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Mara tu match inapotambuliwa unaweza kuanzisha relay, SMB/WMI/WinRM PtH, au ku-re-crack NT hash kwa masks/rules offline.

## Enumerating Active Directory WITH credentials/session

Kwa hatua hii unahitaji kuwa ume-compromise credentials au session ya valid domain account. Ikiwa una credentials halali au shell kama domain user, **kumbuka kwamba chaguzi zilizotajwa hapo awali bado ni njia za kukomomoa watumiaji wengine.**

Kabla ya kuanza authenticated enumeration unapaswa kujua ni nini **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kuwa ume-kompromised account ni **hatua kubwa kuanza kukomomoa domain nzima**, kwa sababu utaweza kuanza **Active Directory Enumeration:**

Kuhusu [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila user inayoweza kuwa vunerable, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya usernames yote** na kujaribu password ya account iliyokomomolewa, empty passwords na passwords mpya zinazoonekana kuahidi.

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

Ni rahisi sana kupata usernames zote za domain kutoka Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Kwenye Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana ndogo, hii ndiyo sehemu muhimu zaidi ya yote. Fungua links (hasa zile za cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuchunguza domain na fanya mazoezi mpaka ujisikie una utaalamu. Wakati wa assessment, hili litakuwa wakati muhimu wa kupata njia yako kwa DA au kuamua kuwa hakuna kinachowezekana.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na services zinazohusishwa na user accounts na ku-crack encryption yao—ambayo inategemea user passwords—**offline**.

Habari zaidi:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Mara tu utakapopata credentials unaweza kuangalia kama una access kwa **machine** yoyote. Kwa hili, unaweza kutumia **CrackMapExec** kujaribu ku-connect kwenye servers kadhaa kwa protocols tofauti, kulingana na results za port scans zako.

### Local Privilege Escalation

Ikiwa ume-kompromised credentials au session kama regular domain user na una **access** na user huyu kwa **machine** yoyote ndani ya domain, jaribu kupata njia ya **escalate privileges locally na kutafuta credentials**. Hii ni kwa sababu ni kwa local administrator tu utakapoweza **dump hashes za watumiaji wengine** kwenye memory (LSASS) na kwa karibu (SAM).

Kuna ukurasa kamili kwenye kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni jambo **lisilotabirika** kupata **tickets** kwenye user wa sasa zinazokupa ruhusa ya kufikia rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umefanikiwa kuorodhesha Active Directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kuwa na uwezo wa kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack).

### Looks for Creds in Computer Shares | SMB Shares

Sasa baada ya kuwa na baadhi ya credentials za msingi unapaswa kuangalia kama unaweza **kupata** faili yoyote **inyoshirikishwa ndani ya AD** ambayo inaweza kuwa ya umuhimu. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha ya kurudia-rudia (na zaidi ikiwa utakuta mamia ya nyaraka unazohitaji kuangalia).

[**Fuata kiungo hiki kujifunza kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **access other PCs or shares** unaweza **place files** (kama SCF file) ambazo, zikifikiwa kwa njia yoyote, zita**trigger an NTLM authentication against you** ili uweze **steal** **NTLM challenge** ili kuichakata:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Urahoa huu uliwapa mtumiaji yeyote aliyethibitishwa uwezo wa **compromise the domain controller**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zifuatazo mtumiaji wa kawaida wa domain haitoshi, unahitaji privileges/credentials maalum ili kutekeleza mashambulizi haya.**

### Hash extraction

Kwa bahati umeweza **compromise some local admin** account kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ikijumuisha relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa dump hashes zote zilizomo kwenye memory na za ndani.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya mtumiaji**, unaweza kuitumia ku**impersonate** mtumiaji huyo.\
Unahitaji kutumia **tool** itakayefanya **NTLM authentication using** hiyo **hash**, **au** unaweza kuunda sessionlogon mpya na **inject** hiyo **hash** ndani ya **LSASS**, hivyo wakati wowote **NTLM authentication** itakapofanyika, hiyo **hash itatumika.** Chaguo la mwisho ndilo lifanyalo mimikatz.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia user NTLM hash kuomba Kerberos tickets**, kama mbadala wa kawaida wa Pass The Hash juu ya protocol ya NTLM. Kwa hivyo, inaweza kuwa **hasa muhimu kwenye mitandao ambapo NTLM protocol imezimwa** na ni **Kerberos pekee** inayoruhusiwa kama protocol ya uthibitisho.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika njia ya shambulio ya **Pass The Ticket (PTT)**, washambuliaji **kunyang'anya authentication ticket ya mtumiaji** badala ya password au hash. Tiketi hii iliyonyangwa kisha inatumika ku**impersonate the user**, kupata upatikanaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrato**r unapaswa kujaribu **login locally** kwenye **PCs** nyingine kwa kutumia hizo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hili ni **lenye kelele nyingi** na **LAPS** lingepunguza.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana ruhusa za **kufikia MSSQL instances**, anaweza kuitumia **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inafanya kazi kama SA), **kuiba** NetNTLM **hash** au hata kufanya **relay attack**.\
Pia, ikiwa instance ya MSSQL imetajwa kuwa trusted (database link) na instance tofauti ya MSSQL. Ikiwa mtumiaji ana ruhusa juu ya database inayotumiwa kwa kuaminiana, atakuwa na uwezo wa **kukutumia uhusiano wa uaminifu kutekeleza queries pia kwenye instance nyingine**. Uaminifu hizi zinaweza kuunganishwa mnyororo na wakati fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambapo anaweza kutekeleza amri.\
**Viungo kati ya databases hufanya kazi hata kupitia forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory na deployment suites mara nyingi zinafunua njia zenye nguvu za kupata credentials na code execution. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ikiwa utakuta kitu chochote cha Computer chenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una vibali vya domain kwenye kompyuta hiyo, utaweza kuchoma TGTs kutoka kwenye memory ya watumiaji wote wanaoingia kwenye kompyuta.\
Kwa hivyo, ikiwa **Domain Admin anafungua akaunti kwenye kompyuta**, utaweza kuchoma TGT yake na kumfanyia impersonate kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **kuathiri kwa moja Print Server** (tumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta imeruhusiwa kwa "Constrained Delegation" itakuwa na uwezo wa **kuiga mtumiaji yeyote ili kufikia baadhi ya huduma kwenye kompyuta**.\
Kisha, ikiwa utaweza **kuiba hash** ya mtumiaji/kompyuta hii utaweza **kuiga mtumiaji yeyote** (hata domain admins) ili kufikia huduma fulani.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** juu ya kitu cha Active Directory cha kompyuta ya mbali kunaruhusu kupata code execution kwa **vibali vilivyoongezwa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyevamiwa anaweza kuwa na baadhi ya **vibali vya kuvutia juu ya baadhi ya vitu vya domain** ambao yanaweza kukuruhusu **kusogea** lateral/**kupanda** kwa vibali.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua **Spool service inayo sikia** ndani ya domain kunaweza **kutumika vibaya** kupata **credentials mpya** na **kupandisha vibali**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** wananufaika na **kuingia** kwenye **mashine iliyovamiwa**, inawezekana **kukusanya credentials kutoka kwenye memory** na hata **kuchoma beacons ndani ya michakato yao** ili kuwaiga.\
Kawaida watumiaji watafikiwa mfumo kwa RDP, hivyo hapa kuna jinsi ya kufanya mashambulizi machache juu ya vikao vya RDP vya watu wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **neno la siri la local Administrator** kwenye kompyuta zilizojiunga na domain, kuhakikisha lina **nasibu**, la kipekee, na linabadilishwa mara kwa mara. Maneno haya ya siri huhifadhiwa katika Active Directory na upatikanaji wake unadhibitiwa kupitia ACLs kwa watumiaji walioruhusiwa tu. Ukiwa na ruhusa za kutosha za kuona maneno haya ya siri, kuhamia kwenye kompyuta nyingine kunaweza kuwa rahisi.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwa mashine iliyovamiwa kunaweza kuwa njia ya kupandisha vibali ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **templates zilizo hatarifu** zimewezeshwa inawezekana kuzitumia ili kupandisha vibali:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara unapopata ruhusa za **Domain Admin** au bora zaidi **Enterprise Admin**, unaweza **kuchoma** **database ya domain**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya mbinu zilizoelezewa hapo juu zinaweza kutumika kwa persistence.\
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

Shambulio la **Silver Ticket** linaumba **Ticket Granting Service (TGS) ticket** halali kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya akaunti ya PC**). Njia hii hutumiwa kupata **vibali vya huduma**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulio la **Golden Ticket** linahusisha mwizi kupata **NTLM hash ya akaunti ya krbtgt** katika Active Directory (AD). Akaunti hii ni maalum kwa sababu inatumika kusaini wote **Ticket Granting Tickets (TGTs)**, ambazo ni muhimu kwa uthibitisho ndani ya mtandao wa AD.

Mara mwizi anapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote atakayotaka (shambulio la Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizofunguliwa kwa njia inayoweza **kuepuka mifumo ya kawaida ya kugundua golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za akaunti au kuwa na uwezo wa kuziomba** ni njia nzuri sana ya kuendelea katika akaunti ya mtumiaji (hata kama atabadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia kunawezekana kuhifadhiwa kwa vibali vya juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kitu cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **vikundi vyenye vibali** (kama Domain Admins na Enterprise Admins) kwa kutumia Access Control List (ACL) ya kimsingi kwenye vikundi hivi ili kuzuia mabadiliko yasiyoruhusiwa. Hata hivyo, kipengele hiki kinaweza kutumika vibaya; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo atapata udhibiti mpana juu ya vikundi vyote vyenye vibali. Kifaa hiki cha usalama, kilichokusudiwa kulinda, kinaweza hivyo kurudisha nyuma, kuruhusu ufikiaji usiostahili isipokuwa kisimamiwe kwa uangalifu.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, akaunti ya **local administrator** ipo. Kwa kupata haki za admin kwenye mashine kama hiyo, hash ya local Administrator inaweza kuchomwa kwa kutumia **mimikatz**. Baadaye, mabadiliko ya registry inahitajika ili **kuwezesha matumizi ya password hii**, kuruhusu upatikanaji wa mbali kwa akaunti ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** mtumiaji baadhi ya **ruhusa maalum** juu ya vitu fulani vya domain ambazo zitamruhusu mtumiaji **kupanda vibali** baadaye.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** zinatumiwa **kuhifadhi** **vibali** ambavyo **kitu** kina juu ya **kitu kingine**. Ikiwa unaweza kufanya **mabadiliko madogo** kwenye **security descriptor** ya kitu, unaweza kupata vibali vya kuvutia juu ya kitu hicho bila hitaji la kuwa mwanachama wa kundi lenye vibali.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia darasa la ziada `dynamicObject` kuunda principals/GPOs/DNS records zenye muda mfupi na `entryTTL`/`msDS-Entry-Time-To-Die`; zinasajiliwa kujiua yenyewe bila tombstones, kuifuta ushahidi wa LDAP huku zikiacha SIDs yatakayosalia, viungo vya `gPLink` vilivyovunjika, au majibu ya DNS yaliyo cached (kwa mfano, uchafuzi wa AdminSDHolder ACE au `gPCFileSysPath`/AD-integrated DNS redirects zenye madhara).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** katika memory ili kuweka **password ya ulimwengu mzima**, ikiruhusu ufikiaji kwa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda SSP yako mwenyewe ili **kushika** kwa **clear text** **credentials** zinazotumika kuingia kwenye mashine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Domain Controller mpya** ndani ya AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye vitu vilivyoainishwa **bila** kuacha **logs** kuhusu **mabadiliko**. Unahitaji vibali vya DA na kuwa ndani ya **root domain**.\
Kumbuka kwamba ikiwa utatumia data zisizo sahihi, logs mbaya zitajitokeza.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tumependekeza jinsi ya kupandisha vibali ikiwa una **ruhusa za kutosha kusoma passwords za LAPS**. Hata hivyo, maneno haya ya siri pia yanaweza kutumika **kudumisha persistence**.\
Tazama:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama boundary ya usalama. Hii ina maana kwamba **kudanganya domain moja kunaweza kusababisha Forest nzima kuathiriwa.**

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mekanismo ya usalama inayomruhusu mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Inaunda uunganisho kati ya mifumo ya uthibitisho ya domain hizo mbili, kuruhusu uthibitisho kuzunguka kwa urahisi. Wakati domains zinaweka trust, zinabadilishana na kuhifadhi **vijiti** maalum ndani ya **Domain Controllers (DCs)**, ambavyo ni muhimu kwa uadilifu wa trust.

Katika hali ya kawaida, ikiwa mtumiaji anataka kufikia huduma katika **trusted domain**, lazima kwanza aombe ticket maalum inayojulikana kama **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii imefichwa kwa **key** ya pamoja ambayo domains zote mbili zimeridhia. Mtumiaji kisha huwasilisha TGT hii kwa **DC ya trusted domain** ili kupata ticket ya huduma (**TGS**). Baada ya DC ya trusted domain kuthibitisha inter-realm TGT kwa kutumia key yao ya pamoja na ikiwa ni halali, itatoa TGS, ikimpa mtumiaji ruhusa ya kutumia huduma.

**Hatua**:

1. Kompyuta ya **mtumiaji** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** ili kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)**.
2. DC1 hutoa TGT mpya ikiwa mteja anathibitishwa kwa mafanikio.
3. Mteja kisha anaomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imefichwa kwa **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya trust ya domain ya pande mbili.
5. Mteja huchukua inter-realm TGT kwenda kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia trust key yake iliyoshirikiwa na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 anayeitaka mteja kufikia.
7. Mwishowe, mteja huwasilisha TGS hii kwa server, ambayo imefichwa kwa hash ya akaunti ya server, kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya pande 1 au pande 2**. Katika chaguo la pande 2, domains zote mbili zitawaaminiana, lakini kwenye uhusiano wa **pande 1** moja ya domains itakuwa **trusted** na nyingine itakuwa **trusting** domain. Katika kesi ya mwisho, **utaweza tu kufikia rasilimali ndani ya trusting domain kutoka trusted moja**.

Ikiwa Domain A inamwamini Domain B, A ni domain inayoamini na B ni ile inayotumika kama trusted. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, hii itakuwa **Inbound trust**.

**Mifano tofauti ya uhusiano wa kuamini**

- **Parent-Child Trusts**: Hii ni mpangilio wa kawaida ndani ya forest moja, ambapo domain mtoto kwa kawaida ina two-way transitive trust na domain mzazi. Kwa ujumla, hii inamaanisha ombi la uthibitisho linaweza kupitishwa kwa urahisi kati ya mzazi na mtoto.
- **Cross-link Trusts**: Zitambulika kama "shortcut trusts," hizi zinateuliwa kati ya child domains kufupisha mchakato wa rufaa. Katika forests tata, rufaa za uthibitisho kawaida zinapaswa kusafiri hadi kwenye mizizi ya forest kisha kushuka hadi domain lengwa. Kwa kuunda cross-links, safari inafupishwa, jambo ambalo ni muhimu hasa katika mazingira yaliyoenea kijiografia.
- **External Trusts**: Hizi zinaanzishwa kati ya domains tofauti, zisizohusiana na mara nyingi ni non-transitive kwa asili. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts zinatumika kwa kufikia rasilimali katika domain nje ya forest ya sasa ambayo haijawa na forest trust. Usalama unaimarishwa kupitia SID filtering na external trusts.
- **Tree-root Trusts**: Trusts hizi zinaanzishwa moja kwa moja kati ya forest root domain na tree root mpya inayoongezwa. Ingawa hazikutambulika mara nyingi, tree-root trusts ni muhimu kwa kuongeza miti mpya ya domain kwenye forest, kuwaruhusu kutunza jina la kipekee la domain na kuhakikisha two-way transitivity. Maelezo zaidi yanapatikana kwenye [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya mizizi ya forest mbili, na pia inatekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Trusts hizi zinaanzishwa na domains zisizo za Windows, zinazofuata [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos. MIT trusts ni maalum zaidi na zinahudumia mazingira yanayohitaji kuunganishwa na mifumo ya Kerberos nje ya mfumo wa Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust unaweza pia kuwa **transitive** (A inaamini B, B inaamini C, basi A inaamini C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (pande zote zinawaamini) au kama **one-way trust** (moja tu inamuamini mwingine).

### Attack Path

1. **Taftisha** uhusiano wa kuamini
2. Angalia kama kuna **security principal** (user/group/computer) ana **ufikiaji** kwa rasilimali za **domain nyingine**, labda kupitia entries za ACE au kwa kuwa katika vikundi vya domain nyingine. Tafuta **uhusiano kati ya domains** (trust iliumbwa kwa hili pengine).
1. kerberoast katika kesi hii inaweza kuwa chaguo jingine.
3. **Vamia** **akaunti** ambazo zinaweza **kupitisha** kupitia domains.

Washambuliaji wanaweza kupata ufikiaji wa rasilimali katika domain nyingine kwa njia tatu kuu:

- **Uanachama wa Kikundi cha Kanda (Local Group Membership)**: Principals wanaweza kuongezwa katika vikundi vya local kwenye mashine, kama kundi la “Administrators” kwenye server, kuwapa udhibiti mkubwa wa mashine hiyo.
- **Uanachama wa Kikundi cha Domain ya Nje (Foreign Domain Group Membership)**: Principals pia wanaweza kuwa wanachama wa vikundi ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii unategemea aina ya trust na wigo wa kundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa kwenye **ACL**, hasa kama sehemu ya **ACEs** ndani ya **DACL**, kuwapa ufikiaji wa rasilimali maalum. Kwa wale wanaotaka kuingia kwa undani katika mechanics za ACLs, DACLs, na ACEs, whitepaper iliyoitwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali isiyoweza kupuuzwa.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kutafuta foreign security principals kwenye domain. Hawa watakuwa watumiaji/vikundi kutoka **domain/forest ya nje**.

Unaweza kuangalia hii katika **Bloodhound** au kwa kutumia powerview:
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
> Kuna **2 trusted keys**, moja kwa _Child --> Parent_ na nyingine kwa _Parent_ --> _Child_.\
> Unaweza kuona ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Pandisha hadhi kuwa Enterprise admin kwenye child/parent domain kwa kutumia trust kwa SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Ni muhimu kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa. Configuration NC inafanya kazi kama hazina kuu ya data za usanidi kote katika forest katika mazingira ya Active Directory (AD). Data hii inaripotiwa kwa kila Domain Controller (DC) ndani ya forest, na DC zinazoweza kuandikwa zikiweka nakala inayoweza kuandikwa ya Configuration NC. Ili kuitekeleza, lazima uwe na **SYSTEM privileges on a DC**, ikiwezekana DC ya child.

**Link GPO to root DC site**

Sites container ya Configuration NC inajumuisha taarifa kuhusu tovuti za kompyuta zote zilizounganishwa na domain ndani ya forest ya AD. Kwa kufanya kazi ukiwa na **SYSTEM privileges on any DC**, mashambulizi yanaweza ku-link GPOs kwa root DC sites. Hatua hii inaweza kuhatarisha root domain kwa kuibadilisha policies zinazotumika kwa sites hizi.

Kwa maelezo ya kina, unaweza kuchunguza utafiti wa [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Vector ya shambulio inahusisha kulenga gMSA zenye hadhi ndani ya domain. KDS Root key, muhimu kwa kuhesabu passwords za gMSAs, imehifadhiwa ndani ya Configuration NC. Ukiwa na **SYSTEM privileges on any DC**, inawezekana kupata KDS Root key na kuhesabu passwords za gMSA yoyote kote forest.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Mbinu hii inahitaji uvumilivu, kusubiri uundaji wa vitu vipya vyenye hadhi ndani ya AD. Ukiwa na **SYSTEM privileges**, mshambuliaji anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili juu ya madarasa yote. Hii inaweza kusababisha upatikanaji usioruhusiwa na udhibiti juu ya AD objects zilizoundwa hivi karibuni.

Soma zaidi: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga kudhibiti Public Key Infrastructure (PKI) objects ili kuunda certificate template inayoruhusu authentication kama mtumiaji yeyote ndani ya forest. Kwa kuwa PKI objects ziko ndani ya Configuration NC, kuathiri writable child DC kunaruhusu utekelezaji wa ESC5 attacks.

Maelezo zaidi yanaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika matukio yasiyo na ADCS, mshambuliaji anaweza kuanzisha vipengele vinavyohitajika, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika senario hii **domain yako imeaminika** na domain ya nje ikikupa **idhini zisizojulikana** juu yake. Utahitaji kubaini **ni principals gani wa domain yako wana upatikanaji gani juu ya domain ya nje** kisha ujaribu ku-exploit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
Katika senario hii **domain yako** inampa **idhini** mhusika kutoka **domain tofauti**.

Hata hivyo, wakati **domain inapoaminika** na domain inayoiamini, domain inayoominika **huunda mtumiaji** mwenye **jina linaloweza kutabiriwa** ambaye anatumia kama **nenosiri nenosiri la kuaminika**. Hii inamaanisha kuwa inawezekana **kupata ufikiaji kwa mtumiaji kutoka domain inayoiamini ili kuingia ndani ya domain inayoominika** ili kuitambua na kujaribu kuinua vibali zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuharibu domain inayoominika ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo wa kinyume** wa uaminifu wa domain (sio ya kawaida sana).

Njia nyingine ya kuharibu domain inayoominika ni kusubiri katika mashine ambapo **mtumiaji kutoka domain inayoominika anaweza kufikia** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code kwenye mchakato wa kikao cha RDP na **kupata ufikiaji kwa domain asili ya mwathiriwa** kutoka hapo.\
Zaidi ya hayo, ikiwa **mwathiriwa ameunganisha diski ngumu yake**, kutoka kwa mchakato wa **RDP session** mshambuliaji anaweza kuhifadhi **backdoors** katika **folda ya startup ya diski ngumu**. Mbinu hii huitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya uaminifu wa domain

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya SID history across forest trusts inapunguzwa na SID Filtering, ambayo imewezeshwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikichukulia forest, badala ya domain, kama mpaka wa usalama kama msimamo wa Microsoft.
- Hata hivyo, kuna tatizo: SID filtering inaweza kuvuruga programu na ufikiaji wa watumiaji, ikasababisha mara kwa mara kuzimwa kwake.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication kunahakikisha kwamba watumiaji kutoka misitu miwili hawathibitishwi moja kwa moja. Badala yake, ruhusa zilizoelezwa wazi zinahitajika ili watumiaji wapate kufikia domains na servers ndani ya domain inayoiamini au forest.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya matumizi mabaya ya writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Matumizi mabaya ya AD yanayotokana na LDAP kwenye On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) inatekeleza upya primitives za LDAP za mtindo bloodyAD kama x64 Beacon Object Files zinazotumika kabisa ndani ya on-host implant (mfano, Adaptix C2). Waendeshaji hukusanya pack kwa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, wanapakia `ldap.axs`, na kisha wanaitisha `ldap <subcommand>` kutoka kwa beacon. Trafiki yote inatumia muktadha wa usalama wa logon wa sasa juu ya LDAP (389) na signing/sealing au LDAPS (636) na kuamini kwa auto certificate, hivyo hakuna socks proxies au artifacts za diski zinahitajika.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` zitatathmini majina mafupi / OU paths kuwa DNs kamili na kutoa vitu vinavyolingana.
- `get-object`, `get-attribute`, and `get-domaininfo` huvuta sifa zozote (kijumuisha security descriptors) pamoja na metadata ya forest/domain kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` zinafichua roasting candidates, settings za delegation, na descriptors zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` and `get-writable --detailed` huchambua DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na urithi, zikitoa malengo ya papo kwa papo kwa ajili ya kuinua vibali kwa ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) zinamruhusu operator kuandaa principals mpya au machine accounts popote ambapo OU rights zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` hu-hijack targets moja kwa moja mara tu write-property rights zinapopatikana.
- ACL-focused commands kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa password resets, group membership control, au DCSync replication privileges bila kuacha artifacts za PowerShell/ADSI. Viambatanisho vya `remove-*` hushughulikia kuondoa ACEs zilizowekwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hufanya instantaneously user iliyokompleka kuwa Kerberoastable; `add-asreproastable` (UAC toggle) huweka alama kwa AS-REP roasting bila kugusa password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) hubadilisha `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, zikiruhusu njia za kushambulia za constrained/unconstrained/RBCD na kuondoa haja ya remote PowerShell au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inaingiza SIDs zilizo na hadhi ya juu kwenye SID history ya principal inayodhibitiwa (see [SID-History Injection](sid-history-injection.md)), ikitoa urithi wa ufikiaji kwa njia ya siri kabisa kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya kompyuta au watumiaji, ikimruhusu mshambuliaji kuvuta mali ndani ya OUs ambapo delegated rights tayari zipo kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zilizo na mipaka madhubuti (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) zinaruhusu rollback haraka baada ya operator kuvuna credentials au persistence, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Jifunze zaidi kuhusu jinsi ya kulinda credentials hapa.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inashauriwa kwamba Domain Admins wanapaswa kuruhusiwa kuingia tu kwenye Domain Controllers, kuepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Services hazipaswi kuendeshwa na Domain Admin (DA) privileges ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji DA privileges, muda wao unapaswa kufungwa. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Fanya audit ya Event IDs 2889/3074/3075 kisha enforce LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia jaribio za LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Kutumia mbinu za udanganyifu kunajumuisha kuweka mtego, kama watumiaji au kompyuta za kuiga, zenye sifa kama passwords zisizokufa au alama za Trusted for Delegation. Njia ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaweka kwenye vikundi vya high privilege.
- Mfano wa vitendo unajumuisha kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi juu ya deploying deception techniques zinapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Viashiria vinavyoshuku vinajumuisha ObjectSID isiyo ya kawaida, logons zisizo nyingi, tarehe za uundaji, na idadi ndogo ya jaribio za password zilizokosewa.
- **General Indicators**: Kulinganisha attributes za vitu vinavyoweza kuwa decoy na zile za vitu halisi kunaweza kufichua utofauti. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu huo.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuepuka utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia vitufe vya **aes** kwa uundaji wa ticket husaidia kuepuka utambuzi kwa kutokupungua hadi NTLM.
- **DCSync Attacks**: Inashauriwa kutekeleza kutoka kwenye non-Domain Controller ili kuepuka utambuzi wa ATA, kwa kuwa utekelezaji wa moja kwa moja kutoka kwa Domain Controller utaamsha alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
