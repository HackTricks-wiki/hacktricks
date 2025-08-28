# Mbinu za Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa Msingi

**Active Directory** ni teknolojia ya msingi, inayowezesha **network administrators** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa ili iweze kupanuka, ikisaidia kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** zinazoweza kudhibitiwa, sambamba na kudhibiti **access rights** kwa ngazi mbalimbali.

Muundo wa **Active Directory** unajumuisha tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** ni mkusanyiko wa objects, kama **users** au **devices**, zinazoshiriki database moja. **Trees** ni makundi ya domains haya yaliyounganishwa na muundo wa pamoja, na **forest** ni mkusanyiko wa trees nyingi, zilizounganishwa kupitia **trust relationships**, zikounda tabaka la juu kabisa la muundo wa shirika. Haki maalum za **access** na **communication** zinaweza kutengwa katika kila moja ya ngazi hizi.

Dhana muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Ina taarifa zote zinazohusiana na Active Directory objects.
2. **Object** – Inaonyesha vitu ndani ya directory, ikiwa ni pamoja na **users**, **groups**, au **shared folders**.
3. **Domain** – Hutoa chombo cha kuhifadhia directory objects, na inawezekana kuwa na domains nyingi ndani ya **forest**, kila moja ikiweka mkusanyiko wake wa objects.
4. **Tree** – Makundi ya domains yanayoshiriki domain mzazi.
5. **Forest** – Juu zaidi ya muundo wa shirika katika Active Directory, inayojumuisha trees kadhaa zenye **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inaleta uhifadhi wa data kwa njia ya kati na kusimamia mwingiliano kati ya **users** na **domains**, ikijumuisha **authentication** na uwezo wa **search**.
2. **Certificate Services** – Inasimamia utengenezaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Inasaidia programu zilizo na directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** ili kuthibitisha watumiaji kwenye web applications nyingi kwa kikao kimoja.
5. **Rights Management** – Inasaidia kulinda vifaa vya hakimiliki kwa kudhibiti usambazaji na matumizi yasiyoidhinishwa.
6. **DNS Service** – Muhimu kwa kutatua **domain names**.

Kwa maelezo zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji kuelewa vizuri mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kuchukua mengi kwenye [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muhtasari wa haraka wa amri ambazo unaweza kuendesha ku-enumerate/exploit AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa unaweza tu kupata ufikiaji wa mazingira ya AD lakini huna credentials/sessions unaweza:

- **Pentest the network:**
- Scan the network, pata machines na ports zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerating DNS inaweza kutoa taarifa kuhusu servers muhimu ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kwa maelezo zaidi kuhusu jinsi ya kufanya hili.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye toleo za kisasa za Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina kuhusu jinsi ya ku-enumerate SMB server unaweza kupatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina kuhusu jinsi ya ku-enumerate LDAP unaweza kupatikana hapa (lipa **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Patia host ufikiaji kwa **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Choma usernames/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, huduma (hasa web) ndani ya mazingira ya domain na pia kutoka kwa yaliyopo hadharani.
- Ikiwa utapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu kanuni mbalimbali za AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Kanuni zinazoenea zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _random_ na namba 3 _random_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ikitupa nafasi ya kubaini kuwa username ilikuwa batili. **Valid usernames** zitapokea au TGT katika majibu ya **AS-REP** au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa mtumiaji anaombiwa kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya kiolesura cha MS-NRPC (Netlogon) kwenye domain controllers. Mbinu hii inaita function ya `DsrGetDcNameEx2` baada ya kubind MS-NRPC interface ili kukagua kama user au computer ipo bila credentials yoyote. Chombo cha [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) kinatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikiwa umepata moja ya seva hizi kwenye mtandao unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Unaweza kupata orodha za majina ya watumiaji kwenye [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  na hii ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi katika kampuni** kutoka hatua ya recon uliyopaswa kuwa umefanya kabla. Kwa jina na jina la ukoo unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuzalisha majina ya watumiaji yanayoweza kuwa halali.

### Knowing one or several usernames

Sawa, kwa hivyo unajua tayari una jina la mtumiaji halali lakini hakuna nywila... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **haina** sifa _DONT_REQ_PREAUTH_ unaweza **kuomba ujumbe AS_REP** kwa mtumiaji huyo ambao utakuwa na baadhi ya data iliyosimbwa kwa utengenezaji wa nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Jaribu nywila zinazotumika zaidi kwa kila mmoja wa watumiaji uliogundua, labda mtumiaji mwingine anatumia nywila mbaya (kumbuka sera ya nywila!).
- Kumbuka kwamba pia unaweza **spray OWA servers** ili kujaribu kupata ufikiaji wa seva za barua za watumiaji.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza kupata baadhi ya challenge **hashes** za ku-crack kwa kufanya **poisoning** kwa baadhi ya protokoli za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa kuorodhesha Active Directory utakuwa na barua pepe zaidi na uelewa bora wa mtandao. Unaweza kujaribu kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa mazingira ya AD.

### Steal NTLM Creds

Iwapo unaweza **kupata access kwenye PC nyingine au shares** kwa kutumia **null or guest user** unaweza **kuweka files** (kama SCF file) ambazo mchakato wowote wa kuzipata unaweza **trigger an NTLM authentication against you**, ili uweze **steal** the **NTLM challenge** na kuikwepa/kuicrack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Kwa hatua hii unahitaji kuwa umeharibu **credentials au session ya account halali ya domain.** Ikiwa una credentials halali au shell kama domain user, **kumbuka kwamba chaguzi zilizotajwa hapo awali bado ni njia za kumdhuru watumiaji wengine**.

Kabla ya kuanza enumeration iliyothibitishwa unapaswa kuelewa tatizo la **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kuwa umedhulumiwa akaunti ni **hatua kubwa ya kuanza kudhulumu domain nzima**, kwani utakuwa na uwezo wa kuanza **Active Directory Enumeration:**

Kuhusu [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji anayehisiwa kuwa hatarini, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu nywila za akaunti iliyodhulumiwa, nywila tupu na nywila mpya zinazotarajiwa.

- Unaweza kutumia [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Pia unaweza kutumia [**powershell for recon**](../basic-powershell-for-pentesters/index.html) ambayo itakuwa ya kimya zaidi
- Pia unaweza [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kukusanya taarifa za kina zaidi
- Zana nyingine nzuri kwa recon katika Active Directory ni [**BloodHound**](bloodhound.md). Si **stealthy sana** (kulingana na mbinu za ukusanyaji unazotumia), lakini **ikiwa haujali** kuhusu hilo, inastahili kujaribiwa. Tafuta wapi watumiaji wanaweza RDP, tafuta njia za kuingia kwenye makundi mengine, n.k.
- **Zana nyingine za kiotomatiki za AD enumeration ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) kwani zinaweza kuwa na taarifa za kuvutia.
- Zana yenye GUI unaweza kutumia kuorodhesha directory ni **AdExplorer.exe** kutoka kwa **SysInternal** Suite.
- Pia unaweza kutafuta kwenye database ya LDAP kwa kutumia **ldapsearch** kutafuta credentials katika fields _userPassword_ & _unixUserPassword_, au hata katika _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
- Ikiwa unatumia **Linux**, unaweza pia kuorodhesha domain ukitumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Pia unaweza kujaribu zana za kiotomatiki kama:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu ya Enumeration inaonekana fupi hii ndiyo sehemu muhimu zaidi ya yote. Fungua viungo (hasa ile za cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuorodhesha domain na fanya mazoezi hadi ujiamini. Wakati wa assessment, hili ndilo kipindi muhimu kupata njia yako ya DA au kuamua kuwa hakuna cha kufanya.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumika na services zinazohusishwa na akaunti za watumiaji na ku-crack usimbaji wake—ambao unategemea nywila za watumiaji—**offline**.

Zaidi kuhusu hili katika:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Mara tu unapopata baadhi ya credentials unaweza kuangalia kama una ufikiaji wa yoyote ya **machines**. Kwa hiyo, unaweza kutumia **CrackMapExec** kujaribu kuunganishwa kwenye seva kadhaa kwa protokoli tofauti, kulingana na skani zako za ports.

### Local Privilege Escalation

Ikiwa umeharibu credentials au session kama domain user wa kawaida na una **access** kwa mtumiaji huyu kwenye **machine yoyote kwenye domain** unapaswa kujaribu kupata njia ya **escalate privileges locally and looting for credentials**. Hii ni kwa sababu ni kwa tu ukiwa na local administrator privileges ndipo utaweza **dump hashes of other users** kwenye memory (LSASS) na ndani ya mfumo (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **sio rahisi** sana kwamba utapata **tickets** kwenye mtumiaji wa sasa ambazo zinakupa ruhusa ya kufikia rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umefanikiwa kuorodhesha active directory utaweza kuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kuweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una baadhi ya basic credentials unapaswa kuangalia kama unaweza **kupata** faili zozote **zinazovutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mikono lakini ni kazi ya kuchosha sana ya kurudia-rudia (hasa ikiwa utakuta mamia ya nyaraka unazohitaji kukagua).

[**Fuata kiungo hiki ili ujifunze kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **access other PCs or shares** unaweza **kuweka faili** (kama faili ya SCF) ambazo zikigundulika kwa namna yoyote zita**sababisha uthibitisho wa NTLM dhidi yako** ili uweze **kuiba** **NTLM challenge** ili kuichakua:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hitilafu hii iliruhusu mtumiaji yeyote aliyethibitishwa **kuvamia domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zifuatazo mtumiaji wa kawaida wa domain haitoshi, unahitaji baadhi ya privileges/credentials maalum ili kutekeleza mashambulizi haya.**

### Hash extraction

Tunatumai umefanikiwa **kupata udhibiti wa account ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa kutoa hashes zote kutoka kwenye memory na kwa ndani.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapokuwa na hash ya mtumiaji**, unaweza kuitumia **impersonate** it.\
Unahitaji kutumia **tool** itakayefanya **NTLM authentication ikitumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **inject** hiyo **hash** ndani ya **LSASS**, ili wakati wowote **NTLM authentication** itakapotendeka, hiyo **hash itatumika.** Chaguo la mwisho ndilo linalofanywa na mimikatz.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia NTLM hash ya mtumiaji kuomba Kerberos tickets**, kama mbadala kwa Pass The Hash kawaida juu ya protocol ya NTLM. Hivyo, hii inaweza kuwa hasa **faa katika mitandao ambapo NTLM protocol imezimwa** na tu **Kerberos inaruhusiwa** kama protocol ya uthibitisho.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulio ya **Pass The Ticket (PTT)**, wavamizi **huiba tiketi ya uthibitisho ya mtumiaji** badala ya nenosiri au thamani za hash. Tiketi hii iliyochukuliwa kisha inatumika **impersonate** mtumiaji, kupata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **login locally** kwenye **PCs** nyingine ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hili ni **kelele** sana na **LAPS** lingepunguza hilo.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana vibali vya **access MSSQL instances**, anaweza kutumia hilo kwa **execute commands** kwenye mwenyeji wa MSSQL (ikiwa inaendesha kama SA), **steal** NetNTLM **hash** au hata kufanya **relay** **attack**.\
Pia, ikiwa instance ya MSSQL inaaminika (database link) na instance tofauti ya MSSQL. Ikiwa mtumiaji ana vibali kwenye database iliyotumika kama trusted, atakuwa na uwezo wa **use the trust relationship to execute queries also in the other instance**. Hii trust zinaweza kuunganishwa mnyororo na katika hatua fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambapo anaweza **execute commands**.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite za upande wa tatu za inventory na deployment mara nyingi zinaonyesha njia zenye nguvu za kupata credentials na code execution. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ikiwa unakuta Computer object yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una domain privileges kwenye kompyuta hiyo, utaweza dump TGTs kutoka memory ya watumiaji wote wanaoingia kwenye kompyuta hiyo.\
Kwa hiyo, ikiwa **Domain Admin** anaingia kwenye kompyuta, utaweza dump TGT yake na kumfanyia impersonate kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **automatically compromise a Print Server** (atumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta imeruhusiwa kwa "Constrained Delegation" itakuwa na uwezo wa **impersonate any user to access some services in a computer**.\
Kisha, ikiwa wewe **compromise the hash** ya mtumiaji/kompyuta hii utaweza **impersonate any user** (hata domain admins) kuingia kwenye baadhi ya services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** kwenye Active Directory object ya kompyuta ya mbali kunaruhusu kupata code execution kwa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyeverengwa anaweza kuwa na baadhi ya **interesting privileges over some domain objects** ambayo yanaweza kumruhusu **move** lateral/**escalate** privileges baadaye.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kupata **Spool service listening** ndani ya domain kunaweza **abused** ili **acquire new credentials** na **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **other users** wana **access** kwenye **compromised** machine, inawezekana **gather credentials from memory** na hata **inject beacons in their processes** ili kuwao impersonate.\
Kawaida watumiaji wataingia mfumo kupitia RDP, hivyo hapa kuna jinsi ya kufanya baadhi ya mashambulizi juu ya sesi za RDP za watu wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **local Administrator password** kwenye kompyuta zilizo joined kwenye domain, kuhakikisha ni **randomized**, ya kipekee, na hubadilishwa mara kwa mara. Nywila hizi zinahifadhiwa ndani ya Active Directory na ufikiaji zinafungiwa kupitia ACLs kwa watumiaji walioidhinishwa tu. Ukiwa na vibali vya kutosha vya kusoma nywila hizi, pivoting kwenda kompyuta nyingine inakuwa inawezekana.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** kutoka kwenye mashine iliyoverengwa inaweza kuwa njia ya ku-escalate privileges ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **vulnerable templates** zimewekwa inaweza kuzitumia ku-escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara baada ya kupata **Domain Admin** au bora zaidi **Enterprise Admin** privileges, unaweza **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya mbinu zilizojadiliwa hapo juu zinaweza kutumika kwa persistence.\
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

Shambulio la **Silver Ticket** linaunda **legitimate Ticket Granting Service (TGS) ticket** kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya PC account**). Njia hii inatumika kupata **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulio la **Golden Ticket** linahusisha mdukuzi kupata **NTLM hash ya krbtgt account** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu inatumika kusaini zote **Ticket Granting Tickets (TGTs)**, ambazo ni muhimu kwa authentication ndani ya mtandao wa AD.

Mara tu mdukuzi anapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote anayotaka (shambulio la Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets lakini zinaufanywa kwa njia inayoweza **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za akaunti au uwezo wa kuziomba** ni njia nzuri ya kukaa persist kwenye akaunti ya mtumiaji (hata kama anabadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia inawezekana kuweka persistence kwa privileges za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kituo cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **privileged groups** (kama Domain Admins na Enterprise Admins) kwa kutumia Access Control List (ACL) ya kawaida kwenye makundi haya ili kuzuia mabadiliko yasiyoruhusiwa. Hata hivyo, kipengele hiki kinaweza kutumika vibaya; ikiwa mdukuzi ata badilisha ACL ya AdminSDHolder kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo atapata udhibiti mkubwa juu ya makundi yote yaliyofaidika. Hatua hii ya usalama, iliyokusudiwa kulinda, inaweza hivyo kurejesha matokeo mabaya, kuruhusu ufikiaji usioidhinishwa isipokuwa ikifuatiliwa kwa karibu.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Katikati ya kila **Domain Controller (DC)**, kuna akaunti ya **local administrator**. Kwa kupata haki za admin kwenye mashine kama hiyo, hash ya Local Administrator inaweza kutolewa kwa kutumia **mimikatz**. Baadaye, mabadiliko kwenye registry ni muhimu ili **enable the use of this password**, kuruhusu ufikiaji wa mbali kwa akaunti ya Local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **give** baadhi ya **special permissions** kwa **user** juu ya vitu maalum vya domain ambazo zitamruhusu mtumiaji **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** zinatumika **kuhifadhi** **permissions** ambazo **object** ina **juu ya** object. Ikiwa unaweza kufanya **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata vibali vyenye faida juu ya object hiyo bila kuhitaji kuwa mwanachama wa kikundi chenye mamlaka.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** ndani ya memory ili kuweka **neno la siri la ulimwengu**, likiwa na ufikiaji wa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP** yako mwenyewe ili **capture** kwa **clear text** **credentials** zinazotumika kuingia kwenye mashine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Domain Controller** mpya katika AD na kuitumia **push attributes** (SIDHistory, SPNs...) kwa vitu vilivyobainishwa **bila** kuacha **logs** kuhusu **mabadiliko**. Unahitaji DA privileges na kuwa ndani ya **root domain**.\
Kumbuka kuwa ikiwa utatumia data isiyo sahihi, logs mbaya zitajitokeza.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tumetoa jinsi ya ku-escalate privileges ikiwa una **enough permission to read LAPS passwords**. Hata hivyo, nywila hizi zinaweza pia kutumika kwa **maintain persistence**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama mpaka wa usalama. Hii ina maana kwamba **kuathiri domain moja kunaweza kusababisha kuathiri Forest yote**.

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mfumo wa usalama unaowezesha mtumiaji kutoka **domain** moja kupata rasilimali katika **domain** nyingine. Inaunda muunganiko kati ya mifumo ya authentication ya domains mbili, ikiruhusu uhakiki wa authentication kuendelea kwa urahisi. Wakati domains zinaweka trust, zinabadilisha na kuweka maalum **keys** ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uaminifu wa trust.

Katika matukio ya kawaida, ikiwa mtumiaji anataka kupata huduma katika **trusted domain**, lazima kwanza aombe ticket maalum inayoitwa **inter-realm TGT** kutoka DC ya domain yake. TGT hii imefungwa kwa **key** iliyoshirikiwa ambayo domains zote mbili zimekubaliana. Mtumiaji kisha anatumia inter-realm TGT hii kwa **DC ya trusted domain** kupata service ticket (**TGS**). Baada ya inter-realm TGT kuthibitishwa na DC ya trusted domain, itatoa TGS, ikimpa mtumiaji ufikiaji wa huduma.

**Steps**:

1. Kompyuta ya **client** katika **Domain 1** inaanzisha mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)**.
2. DC1 hutoa TGT mpya ikiwa client imefanikiwa kuthibitishwa.
3. Kisha client inamuomba **inter-realm TGT** kutoka DC1, ambayo inahitajika ili kupata rasilimali katika **Domain 2**.
4. Inter-realm TGT imefungwa kwa **trust key** iliyoshirikiwa kati ya DC1 na DC2 kama sehemu ya trust ya mwelekeo wa pande mbili.
5. Client inachukua inter-realm TGT kwenda kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia trust key iliyoshirikiwa na, ikiwa ni halali, hutoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 ambayo client anataka kufikia.
7. Mwishowe, client inawasilisha TGS hii kwa server, ambayo imefungwa kwa hash ya account ya server, ili kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa 1 way au 2 ways**. Katika chaguo la 2 ways, domains zote mbili zitakuwa zinaaminiana, lakini katika uhusiano wa **1 way** moja ya domains itakuwa **trusted** na nyingine itakuwa **trusting** domain. Katika kesi ya mwisho, **utakuwa na uwezo wa kupata rasilimali ndani ya trusting domain kutoka trusted domain tu**.

Ikiwa Domain A inamtumaini Domain B, A ndiye trusting domain na B ndiye trusted. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, hii itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Hii ni mpangilio wa kawaida ndani ya forest hiyo hiyo, ambapo child domain ina automatisch two-way transitive trust na parent domain. Hii inamaanisha kuwa maombi ya authentication yanaweza kusafiri kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Zinajulikana kama "shortcut trusts," zinaundwa kati ya child domains ili kuharakisha mchakato wa marejeo. Katika forests tata, marejeo ya authentication kawaida yanapaswa kusafiri hadi kwenye mizizi ya forest kisha kushuka hadi domain lengwa. Kwa kuunda cross-links, safari hiyo inafupishwa, jambo lenye faida hasa katika mazingira yaliyoenea kimwili.
- **External Trusts**: Hizi zimeanzishwa kati ya domains tofauti, zisizo na uhusiano na kwa asili si transitive. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts ni muhimu kwa kupata rasilimali katika domain nje ya forest ya sasa ambayo haijabunganishwa kwa forest trust. Usalama unaboreshwa kupitia SID filtering kwa external trusts.
- **Tree-root Trusts**: Trusts hizi zinaanzishwa moja kwa moja kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazionekani mara kwa mara, tree-root trusts ni muhimu kwa kuongeza miti mpya ya domain kwenye forest, zikiruhusu kudumisha jina la kipekee la domain na kuhakikisha transitivity ya pande mbili. Maelezo zaidi yanapatikana katika [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, na pia inatekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Trusts hizi zinaanzishwa na domains za Kerberos zisizo za Windows, zinazoendana na [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na zinahudumia mazingira yanayohitaji ujumuishaji na mifumo ya Kerberos nje ya ekosistimu ya Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust pia unaweza kuwa **transitive** (A trust B, B trust C, basi A trust C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (pande zote zinaaminiana) au kama **one-way trust** (mmoja tu anamtumaini mwingine).

### Attack Path

1. **Enumerate** uhusiano wa trusting
2. Angalia kama kuna **security principal** (user/group/computer) ana **access** kwa rasilimali za **domain nyingine**, labda kupitia ACE entries au kwa kuwa katika vikundi vya domain nyingine. Angalia **relationships across domains** (trust ilianzishwa kwa madhumuni haya huenda).
1. kerberoast katika hali hii inaweza kuwa chaguo lingine.
3. **Compromise** akaunti ambazo zinaweza **pivot** kupitia domains.

Washambuliaji wanaweza kupata ufikiaji wa rasilimali katika domain nyingine kupitia mekanisimu tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye vikundi vya ndani kwenye mashine, kama kikundi cha “Administrators” kwenye server, kuwaweka na udhibiti mkubwa juu ya mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa vikundi ndani ya domain ya kigeni. Hata hivyo, ufanisi wa mbinu hii hutegemea aina ya trust na wigo wa kikundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kuorodheshwa katika **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, wakiwapa ufikiaji wa rasilimali maalum. Kwa wale wanaotaka kuingia kwa undani zaidi kwenye mekanika za ACLs, DACLs, na ACEs, whitepaper iitwayo “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali muhimu.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals katika domain. Hawa watakuwa user/group kutoka **an external domain/forest**.

Unaweza kuangalia hili kwa kutumia **Bloodhound** au kwa kutumia powerview:
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

Panda hadhi kuwa Enterprise admin kwenye domain ya child/parent kwa kutumia trust na SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Ni muhimu kuelewa jinsi Configuration Naming Context (NC) inaweza kutumiwa. Configuration NC inafanya kazi kama hazina kuu ya data za configuration ndani ya forest katika mazingira ya Active Directory (AD). Data hii inaripukizwa kwa kila Domain Controller (DC) ndani ya forest, na writable DCs zinatunza nakala inayoweza kuandikwa ya Configuration NC. Ili kuifanyia exploit hii, mtu lazima awe na **SYSTEM privileges on a DC**, bora kuwa child DC.

**Link GPO to root DC site**

Container ya Sites ya Configuration NC ina taarifa kuhusu sites za kompyuta zote zilizo joined kwenye domain ndani ya AD forest. Kwa kufanya kazi kwa SYSTEM privileges on any DC, mashambulizi yanaweza ku-link GPOs kwa root DC sites. Kitendo hiki kinaweza kudhoofisha root domain kwa kubadilisha policies zinazotumika kwa sites hizi.

Kwa taarifa za kina, unaweza kusoma utafiti kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia ya shambulio ni kulenga gMSA zenye hadhi ndani ya domain. KDS Root key, muhimu kwa kuhesabu passwords za gMSAs, imehifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges on any DC, inawezekana kupata KDS Root key na kuhesabu passwords za gMSA yoyote ndani ya forest.

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

Mbinu hii inahitaji uvumilivu, kusubiri uundaji wa vitu vipya vya AD zenye hadhi. Ukiwa na SYSTEM privileges, mshambuliaji anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili juu ya classes zote. Hii inaweza kusababisha ufikiaji usioidhinishwa na udhibiti wa vitu vipya vilivyoundwa vya AD.

Soma zaidi kwenye [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda template ya cheti inayoruhusu authentication kama mtumiaji yeyote ndani ya forest. Kwa kuwa vitu vya PKI vipo katika Configuration NC, kudhoofisha writable child DC kunaruhusu utekelezaji wa mashambulizi ya ESC5.

Taarifa zaidi zinaweza kusomwa kwenye [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira yasiyo na ADCS, mshambuliaji ana uwezo wa kuanzisha vipengele vinavyohitajika, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika senario hii **domain yako inategemewa** na domain ya nje ikikupa **ruhusa zisizojulikana** juu yake. Utahitaji kubaini **ni principals gani wa domain yako wana ruhusa gani juu ya domain ya nje** kisha kujaribu kui-exploit:


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
Katika senario hii **your domain** inakuwa **trusting** baadhi ya **privileges** kwa mhusika kutoka **different domains**.

Walakini, wakati **domain is trusted** na domain inayomwamini, domain ya kutegemewa **creates a user** na jina **predictable name** ambalo hutumia kama **password the trusted password**. Hii ina maana kuwa inawezekana **access a user from the trusting domain to get inside the trusted one** ili kuorodhesha (enumerate) na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kumdhalilisha domain iliyotegemewa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **opposite direction** ya uaminiano wa domain (ambayo haipo kwa kawaida).

Njia nyingine ya kumdhalilisha domain iliyotegemewa ni kusubiri kwenye mashine ambako **user from the trusted domain can access** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza nambari ndani ya mchakato wa RDP session na **access the origin domain of the victim** kutoka hapo. Aidha, ikiwa **victim mounted his hard drive**, kutoka kwa mchakato wa **RDP session** mshambuliaji anaweza kuweka **backdoors** kwenye **startup folder of the hard drive**. Mbinu hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya uaminiano wa domain

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia attribute ya SID history kati ya forest trusts hupunguzwa na SID Filtering, ambayo imewashwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikichukulia forest, badala ya domain, kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna tatizo: SID filtering inaweza kusumbua programu na ufikiaji wa watumiaji, na kusababisha mara kwa mara kuzimwa kwake.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication inahakikisha kwamba watumiaji kutoka misitu miwili hawathibitishwi moja kwa moja. Badala yake, ruhusa za wazi zinahitajika kwa watumiaji ili kufikia domains na servers ndani ya domain au forest inayomwamini.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya matumizi mabaya ya writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Kinga za Jumla

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inashauriwa kwamba Domain Admins waruhusiwe kuingia tu kwenye Domain Controllers, kuepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Huduma hazipaswi kuendeshwa zikiwa na Domain Admin (DA) privileges ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji DA privileges, muda wake unapaswa kupunguzwa. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Kutumia udanganyifu kunahusisha kuweka mtego, kama watumiaji wa kudanganya au kompyuta, zenye sifa kama passwords zisizokufa au zimewekewa alama Trusted for Delegation. Mbinu ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye vikundi vyenye privileges za juu.
- Mfano wa vitendo unahusisha kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi kuhusu deploying deception techniques zinapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Viashiria vinavyoshuku vinajumuisha ObjectSID isiyo ya kawaida, logons chache, tarehe za uundaji, na idadi ndogo ya majaribio ya nywila mbaya.
- **General Indicators**: Kuk مقارنة (comparing) sifa za vitu vinavyoweza kuwa decoy na zile za vya kweli kunaweza kufunua tofauti. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua udanganyifu huo.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka enumeration ya session kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia funguo za **aes** kwa uundaji wa tiketi husaidia kuepuka ugunduzi kwa kutoangusha hadi NTLM.
- **DCSync Attacks**: Inashauriwa kutekeleza kutoka non-Domain Controller ili kuepuka utambuzi wa ATA, kwani utekelezaji wa moja kwa moja kutoka Domain Controller utasababisha onyo.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
