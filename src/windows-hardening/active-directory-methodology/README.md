# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari wa Msingi

**Active Directory** ni teknolojia ya msingi inayowezesha **wasimamizi wa mtandao** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa ili iweze kupanuka, ikiruhusu kupanga idadi kubwa ya users katika **groups** na **subgroups** zinazoweza kudhibitiwa, pamoja na kudhibiti **access rights** katika ngazi mbalimbali.

Muundo wa **Active Directory** una tabaka tatu kuu: **domains**, **trees**, na **forests**. **Domain** inajumuisha mkusanyiko wa objects, kama **users** au **devices**, ambao wanashiriki database moja. **Trees** ni vikundi vya domains vinavyohusishwa kwa muundo wa mizizi sawa, na **forest** ni mkusanyiko wa miti mingi zilizo na **trust relationships** kati yao, zikiumba tabaka la juu kabisa la muundo wa shirika. Haki maalum za **access** na **communication** zinaweza kuwekwa katika kila moja ya ngazi hizi.

Misingi muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Ina taarifa zote zinazohusu Active Directory objects.
2. **Object** – Inaonyesha entiti ndani ya directory, ikiwa ni pamoja na **users**, **groups**, au **shared folders**.
3. **Domain** – Inatumika kama kontena la directory objects, na inawezekana domains nyingi kuishi ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kundi la domains zinazoshiriki root domain moja.
5. **Forest** – Ngazi ya juu ya muundo wa shirika ndani ya Active Directory, yenye miti kadhaa na **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha aina mbalimbali za services muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Services hizi ni pamoja na:

1. **Domain Services** – Inaleta hifadhi ya data kwa katikati na kusimamia mwingiliano kati ya **users** na **domains**, ikiwa ni pamoja na **authentication** na functionalities za **search**.
2. **Certificate Services** – Inasimamia uundaji, ugawaji, na usimamizi wa **digital certificates** za usalama.
3. **Lightweight Directory Services** – Inasaidia applications zilizounganishwa na directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Inatoa uwezo wa **single-sign-on** ili ku-authenticate users kwa applications nyingi za wavuti kwa kikao kimoja.
5. **Rights Management** – Inasaidia kulinda nyenzo za hakimiliki kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Muhimu kwa kutatua majina ya **domains**.

Kwa maelezo zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kuelewa jinsi ya **attack an AD** unahitaji kuelewa vizuri mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) kwa muonekano wa haraka wa amri ambazo unaweza kutumia ku-enumerate/exploit AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** kwa kufanya vitendo. Ikiwa utajaribu kufikia mashine kwa anwani ya IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una upatikanaji wa mazingira ya AD lakini huna credentials/sessions yoyote unaweza:

- **Pentest the network:**
- Scan mtandao, pata machines na ports zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Kukusanya taarifa za DNS kunaweza kutoa taarifa kuhusu servers muhimu katika domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Tingalia General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata maelezo zaidi juu ya jinsi ya kufanya hili.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye toleo za kisasa za Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina kuhusu jinsi ya ku-enumerate SMB server unapatikana hapa:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina kuhusu jinsi ya ku-enumerate LDAP unapatikana hapa (lipa **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Kusanya credentials kwa **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Pata access kwa host kwa **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing fake UPnP services with evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, services (hasa web) ndani ya mazingira ya domain na pia kutoka kwa vyanzo vinavyopatikana hadharani.
- Ikiwa utakutana na majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu conventions tofauti za AD **username** ( **read this** ). Conventions zinazotumika sana ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, _herufi 3 za nasibu na namba 3 za nasibu_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia ukurasa wa [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, kutuwezesha kubaini kuwa username ilikuwa batili. **Valid usernames** zitatokea kwa TGT katika jibu la **AS-REP** au kosa _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa user anatakiwa kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya MS-NRPC (Netlogon) interface kwenye domain controllers. Mbinu inaita function ya `DsrGetDcNameEx2` baada ya ku-bind interface ya MS-NRPC ili kuchunguza ikiwa user au computer ipo bila credentials yoyote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) inatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [hapa](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Seva**

Ikiwa umepata moja ya seva hizi kwenye mtandao, unaweza pia kufanya **user enumeration** dhidi yake. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Sawa, hivyo unajua tayari unayo username halali lakini hakuna nywila... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **doesn't have** the attribute _DONT_REQ_PREAUTH_ unaweza **request a AS_REP message** kwa mtumiaji huyo ambayo itakuwa na data iliyosimbwa kwa utengenezaji wa nenosiri la mtumiaji.
- [**Password Spraying**](password-spraying.md): Tujaribu nywila za **kawaida zaidi** kwa kila mmoja wa watumiaji waliogunduliwa, labda mtumiaji fulani anatumia nywila mbaya (kumbuka sera ya nywila!).
- Kumbuka pia unaweza **spray OWA servers** ili kujaribu kupata ufikiaji kwa seva za barua za watumiaji.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza kuwa na uwezo wa kupata baadhi ya challenge **hashes** za kuvunja kwa ku**poison** baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa kuchunguza Active Directory utakuwa na barua pepe zaidi na uelewa bora wa mtandao. Unaweza kuwa na uwezo wa kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa mazingira ya AD.

### Steal NTLM Creds

Ikiwa unaweza **access other PCs or shares** kwa kutumia **null or guest user** unaweza **place files** (kama SCF file) ambazo ikiwa zitafikiwa zitafanya t**rigger an NTLM authentication against you** ili uweze **steal** the **NTLM challenge** ili kuizusha:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Kutafuta Active Directory KWA credentials/session

Kwa hatua hii unahitaji kuwa umepata au kucompromise credentials au session ya akaunti halali ya domain. Ikiwa una credentials halali au shell kama mtumiaji wa domain, **kumbuka kwamba chaguzi zilizotolewa hapo awali bado ni njia za kucompromise watumiaji wengine**.

Kabla ya kuanza authenticated enumeration unapaswa kuelewa tatizo la **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Kuwa umepata akaunti ni hatua kubwa ya kuanza kushambulia domain nzima, kwa sababu utaweza kuanza **Active Directory Enumeration:**

Kuhusu [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji anayeweza kuwa dhaifu, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **list of all the usernames** na kujaribu nywila ya akaunti iliyoporwa, nywila tupu na nywila mpya zinazotarajiwa.

- Unaweza kutumia [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell for recon**](../basic-powershell-for-pentesters/index.html) ambayo itakuwa stealthier
- Unaweza pia [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kutoa taarifa za undani zaidi
- Chombo kingine kizuri kwa recon kwenye Active Directory ni [**BloodHound**](bloodhound.md). Sio **stealthy sana** (inategemea mbinu za kukusanya unazotumia), lakini **kama hukujali** kuhusu hilo, unapaswa kujaribu. Tafuta wapi watumiaji wanaweza RDP, tafuta njia za kufikia vikundi vingine, n.k.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Angalia [**DNS records of the AD**](ad-dns-records.md) kwani zinaweza kuwa na taarifa za kuvutia.
- Chombo chenye GUI unachoweza kutumia kuorodhesha directory ni **AdExplorer.exe** kutoka **SysInternal** Suite.
- Unaweza pia kutafuta kwenye database ya LDAP kwa kutumia **ldapsearch** kutafuta credentials katika fields _userPassword_ & _unixUserPassword_, au hata _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
- Ikiwa unatumia **Linux**, unaweza pia kuorodhesha domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu zana za otomatiki kama:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana ndogo hii ndio sehemu muhimu zaidi ya yote. Fungua viungo (hasa vya cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuorodhesha domain na fanya mazoezi mpaka ujisikie umezoea. Wakati wa tathmini, hili litakuwa kipindi muhimu kupata njia yako ya DA au kuamua kwamba hakuna kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumika na services zinazounganishwa na akaunti za watumiaji na kuvunja usimbaji wake—unaotegemea nywila za watumiaji—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Mara tu unapopata credentials unaweza kuangalia kama una ufikiaji wa mashine yoyote. Kwa kusudi hilo, unaweza kutumia **CrackMapExec** kujaribu kuungana na seva kadhaa kwa protocols tofauti, kulingana na scans zako za ports.

### Local Privilege Escalation

Ikiwa umepata credentials au session kama mtumiaji wa domain wa kawaida na una **access** na mtumiaji huyu kwa **machine yoyote katika domain**, unapaswa kujaribu kupata njia ya kuinua ruhusa kimataifa (local) na kutafuta credentials. Hii ni kwa sababu ni kwa ruhusa ya local administrator pekee utaweza **dump hashes of other users** katika memory (LSASS) na kwa ndani (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **sio kawaida** kwamba utapata **tickets** katika mtumiaji wa sasa zinazokupa idhini ya **access** rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umeweza kuorodhesha Active Directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza pia kufanikiwa kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una baadhi ya credentials za msingi unapaswa kuangalia kama unaweza **kupata** faili zozote **zinazoshirikishwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono, lakini ni kazi ya kuchosha na ya kurudia (hasa kama utakutana na mamia ya hati unazopaswa kukagua).

[**Fuata kiungo hiki ili ujifunze kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kupata access kwa PC nyingine au shares** unaweza **kuweka faili** (kama SCF file) ambazo ikiwa zikitumiwa zitachochea **NTLM authentication dhidi yako**, hivyo unaweza **kuiba** **NTLM challenge** ili kuijaribu ku-crack:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hitilafu hii iliruhusu mtumiaji yeyote aliyethibitishwa **kuhujumu domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zifuatazo mtumiaji wa kawaida wa domain hautoshi, unahitaji baadhi ya privileges/credentials maalum ili kutekeleza mashambulizi haya.**

### Hash extraction

Natumai umeweza **ku-compromise akaunti ya local admin** ukitumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ukiwemo relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [kuinua privileges kwa ndani ya mashine](../windows-local-privilege-escalation/index.html).  
Kisha, ni wakati wa dump hashes zote zilizomo kwenye memory na kwa ndani ya mashine.  
[**Soma ukurasa huu kuhusu njia mbalimbali za kupata hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara unapokuwa na hash ya mtumiaji**, unaweza kuitumia **kujiiga** kama mtumiaji huyo.  
Unahitaji kutumia **tool** itakayefanya **NTLM authentication ikitumia** hash hiyo, **au** unaweza kuunda sessionlogon mpya na **kuingiza** hash hiyo ndani ya **LSASS**, hivyo wakati wowote **NTLM authentication** itakapofanyika, hash hiyo itatumika. Chaguo la mwisho ndilo mimikatz inayofanya.  
[**Soma ukurasa huu kwa taarifa zaidi.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia NTLM hash ya mtumiaji kuomba Kerberos tickets**, kama mbadala wa kawaida Pass The Hash juu ya protocol ya NTLM. Kwa hiyo, inaweza kuwa hasa **faida katika mitandao ambapo NTLM protocol imezimwa** na Kerberos pekee ndiyo inaruhusiwa kama protocol ya uthibitisho.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya kushambulia **Pass The Ticket (PTT)**, wapigaji shambulio **huiba ticket ya uthibitisho ya mtumiaji** badala ya password au thamani za hash. Ticket iliyochukuliwa hiyo hutumika **kujiiga kama mtumiaji**, kupata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrator** unapaswa kujaribu **ku-login locally** kwenye PC nyingine ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kuwa hili ni **la kelele** sana na **LAPS** lingepunguza hili.

### MSSQL Abuse & Trusted Links

Iwapo mtumiaji ana ruhusa ya **kuweza kufikia MSSQL instances**, anaweza kuitumia **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inakimbia kama SA), **kuiba** NetNTLM **hash** au hata kufanya **relay** **attack**.\
Pia, ikiwa instance ya MSSQL inatumiwa kama trusted (database link) na instance nyingine ya MSSQL. Ikiwa mtumiaji ana ruhusa kwenye database inayotumika kama trusted, ataweza **kutumia uhusiano wa kuaminiana kutekeleza queries pia kwenye instance nyingine**. Uaminifu huu unaweza kuunganishwa mnyororo na hatimaye mtumiaji anaweza kupata database iliyopangwa vibaya ambapo anaweza kutekeleza amri.\
**Viungo kati ya database vinafanya kazi hata kati ya forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite za inventory na deployment za tatu mara nyingi zinaonyesha njia zenye nguvu kuelekea kwa credentials na code execution. Angalia:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ikiwa utapata Computer object yoyote yenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una privileges za domain kwenye kompyuta hiyo, utaweza kuchoma TGTs kutoka kwenye memory ya watumiaji wote wanaoingia kwenye kompyuta hiyo.\
Hivyo, ikiwa **Domain Admin** anaingia kwenye kompyuta, utaweza kuchoma TGT yake na kumfanyia impersonate kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **kuathiri moja kwa moja Print Server** (tumaini itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta imeruhusiwa kwa "Constrained Delegation" itaweza **kujifanya mtumiaji mwingine ili kufikia baadhi ya services kwenye kompyuta**.\
Kisha, ukichuna **hash** ya mtumiaji/kompyuta hii utaweza **kujifanya mtumiaji yeyote** (hata domain admins) kufikia baadhi ya services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** kwenye Active Directory object ya kompyuta ya mbali kunaruhusu kupata code execution kwa **privileges zilizoinuliwa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyevamiwa anaweza kuwa na baadhi ya **ruhusa za kuvutia juu ya baadhi ya domain objects** ambazo zinaweza kukuruhusu **kusonga** kwa lateral/**kupanda vyeo** baadaye.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kupata **Spool service inayosikiliza** ndani ya domain kunaweza **kutumika vibaya** ili **kupata credentials mpya** na **kupanda vyeo**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** wanatumia **mashine iliyovamiwa**, inawezekana **kukusanya credentials kutoka memory** na hata **kudingua beacons kwenye michakato yao** ili kujifanya wao.\
Mara nyingi watumiaji watatumia mfumo kwa RDP, hivyo hapa kuna jinsi ya kufanya mashambulizi kadhaa juu ya RDP sessions za wahusika wengine:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** inatoa mfumo wa kusimamia **password ya local Administrator** kwenye kompyuta zilizo join-ndani ya domain, kuhakikisha inakuwa **nasibu**, ya kipekee, na **hubadilishwa** mara kwa mara. Password hizi zinahifadhiwa ndani ya Active Directory na upatikanaji udhibitiwa kupitia ACLs kwa watumiaji walioidhinishwa pekee. Ukiwa na ruhusa za kutosha za kusoma password hizi, inawezekana kupiga pivot kwenda kompyuta nyingine.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwa mashine iliyovamiwa kunaweza kuwa njia ya kupanda vyeo ndani ya mazingira:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **templates zilizo dhaifu** zimewekwa, inawezekana kuzitumia vibaya kupanda vyeo:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara tu unapopata **Domain Admin** au bora zaidi **Enterprise Admin** privileges, unaweza **kuchoma** **database ya domain**: _ntds.dit_.

[**Taarifa zaidi kuhusu shambulio la DCSync zinapatikana hapa**](dcsync.md).

[**Taarifa zaidi kuhusu jinsi ya kuiba NTDS.dit zinapatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya technika zilizopitiwa hapo juu zinaweza kutumika kwa persistence.\
Kwa mfano unaweza:

- Kufanya watumiaji wawe katika hatari ya [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kufanya watumiaji wawe katika hatari ya [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Kutoa ruhusa za [**DCSync**](#dcsync) kwa mtumiaji

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Shambulio la **Silver Ticket** linaunda **TGS ticket halali** kwa service maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya account ya PC**). Njia hii inatumika kupata **ruksa za service**.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulio la **Golden Ticket** linahusisha mwizi kupata **NTLM hash ya account ya krbtgt** katika mazingira ya Active Directory (AD). Account hii ni maalum kwa sababu inatumiwa kusaini zote **Ticket Granting Tickets (TGTs)**, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mwizi anapoipata hash hii, anaweza kuunda **TGTs** kwa account yoyote anayochagua (shambulio la Silver ticket).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizo noshwa kwa njia ambayo **zinaepuka mifumo ya kawaida ya kugundua golden tickets.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za account au uwezo wa kuziomba** ni njia nzuri ya kudumu kwenye account ya mtumiaji (hata akiandika upya password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia inawezekana kudumu ukiwa na privileges za juu ndani ya domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kituo cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **makundi yenye mamlaka** (kama Domain Admins na Enterprise Admins) kwa kutumia ACL ya kawaida kwa makundi haya ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, kipengele hiki kinaweza kutumika vibaya; ikiwa mshambuliaji ataboresha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo atapata udhibiti mkubwa juu ya makundi yote yenye mamlaka. Kipimo hiki cha usalama, kilichokusudiwa kulinda, kinaweza hivyo kurudisha matokeo mabaya, kuruhusu upatikanaji usiofaa isipokuwa ikifuatiliwa kwa ukaribu.

[**Taarifa zaidi kuhusu AdminDSHolder Group hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Katikati ya kila **Domain Controller (DC)**, kuna account ya **local administrator**. Kwa kupata haki za admin kwenye mashine kama hiyo, hash ya local Administrator inaweza kuchomwa kwa kutumia **mimikatz**. Baadaye, urekebishaji wa registry unahitajika ili ** kuwezesha matumizi ya password hii**, ikiruhusu upatikanaji wa mbali kwa account ya local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumpa** baadhi ya **ruhusa maalum** mtumiaji juu ya baadhi ya domain objects ambazo zitamwezesha mtumiaji **kupanda vyeo baadaye**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** zinatumika **kuhifadhi** **ruhusa** ambazo **object** ina **juu ya** object. Ikiwa unaweza kubadilisha tu **kidogo** katika **security descriptor** ya object, unaweza kupata ruhusa za kuvutia juu ya object hiyo bila kuwa mwanachama wa kundi lenye mamlaka.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** kwenye memory ili kuanzisha **password ya ulimwengu mzima**, ikitoa ufikiaji kwa akaunti zote za domain.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kushika** kwa **clear text** **credentials** zinazotumika kufikia mashine.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Domain Controller mpya** katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye objects maalum **bila** kuacha **logs** kuhusu **mabadiliko**. Unahitaji privileges za DA na kuwa ndani ya **root domain**.\
Kumbuka kwamba ukitumia data isiyo sahihi, log mbaya zitajitokeza.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Hapo awali tulijadili jinsi ya kupanda vyeo ikiwa una **ruhusa za kutosha kusoma LAPS passwords**. Hata hivyo, password hizi pia zinaweza kutumika **kudumisha persistence**.\
Angalia:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama ukomo wa usalama. Hii ina maana kwamba **kuvamiwa kwa domain moja kunaweza kusababisha Forest nzima kuvamiwa**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mekanismo ya usalama inayomruhusu mtumiaji kutoka **domain** moja kupata rasilimali katika **domain** nyingine. Kwa msingi, inaunda uhusiano kati ya mifumo ya uthibitishaji ya domain hizi mbili, kuruhusu uthibitishaji kuonekana kwa urahisi. Wakati domain zinazoweka trust, zinabadilisha na kuhifadhi **keys** maalum ndani ya **Domain Controllers (DCs)** zao, ambazo ni muhimu kwa uaminifu wa trust.

Katika dhana ya kawaida, ikiwa mtumiaji anataka kufikia service katika **trusted domain**, lazima kwanza aulize ticket maalum inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii imefichwa kwa kutumia **key** iliyoshirikiwa ambayo domain zote mbili zimekubaliana. Mtumiaji kisha anamuonesha TGT hii **DC ya trusted domain** ili kupata service ticket (**TGS**). Baada ya uhalali wa inter-realm TGT kuthibitishwa na DC ya trusted domain, itatoa TGS, kumruhusu mtumiaji kupata service.

**Hatua**:

1. Kompyuta ya **client** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** yake kuuliza **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 inatoa TGT mpya ikiwa client imethibitishwa kwa mafanikio.
3. Client kisha inaomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imefichwa kwa **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya two-way domain trust.
5. Client inachukua inter-realm TGT kwenda kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia trust key yake iliyoshirikiwa na, ikiwa ni halali, inatoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 ambayo client inataka kufikia.
7. Mwishowe, client inaonyesha TGS hii kwa server, ambayo imefichwa kwa hash ya account ya server, ili kupata ufikiaji wa service katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya njia 1 au njia 2**. Katika chaguo la two-way, domain zote mbili zitawaamini kwa pande zote, lakini katika uhusiano wa **one way** moja ya domain itakuwa **trusted** na nyingine itakuwa **trusting** domain. Katika kesi ya mwisho, **utaweza tu kufikia rasilimali ndani ya trusting domain kutoka trusted domain**.

Ikiwa Domain A inamwamini Domain B, A ni trusting domain na B ni trusted. Zaidi ya hayo, katika **Domain A**, hili litakuwa **Outbound trust**; na katika **Domain B**, hili litakuwa **Inbound trust**.

**Aina tofauti za uhusiano wa kuamini**

- **Parent-Child Trusts**: Hii ni mpangilio wa kawaida ndani ya forest ileile, ambapo child domain ina moja kwa moja two-way transitive trust na parent domain yake. Kimsingi, hii inamaanisha kwamba maombi ya uthibitishaji yanaweza kusafiri kwa urahisi kati ya parent na child.
- **Cross-link Trusts**: Zinajulikana kama "shortcut trusts," hizi zinaanzishwa kati ya child domains ili kuharakisha mchakato wa referral. Katika forests tata, rufaa za uthibitishaji kwa kawaida lazima ziende juu hadi root ya forest kisha chini kwenda domain lengwa. Kwa kuunda cross-links, safari inafupishwa, jambo lenye faida hasa katika mazingira yaliyoenea kwa kijiografia.
- **External Trusts**: Hizi zinaanzishwa kati ya domain tofauti, zisizohusiana na si transitive kwa asili. Kulingana na nyaraka za [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts zinatumika kufikia rasilimali katika domain nje ya forest ya sasa ambayo haijiunganwi na forest trust. Usalama unaimarishwa kupitia SID filtering kwa external trusts.
- **Tree-root Trusts**: Trusti hizi zinaundwa moja kwa moja kati ya forest root domain na tree root mpya iliyoongezwa. Ingawa si za kawaida kukutana nazo, tree-root trusts ni muhimu kwa kuongeza miti mpya ya domain katika forest, kuwawezesha kuwa na jina la domain la kipekee na kuhakikisha transitivity ya njia mbili. Taarifa zaidi zipo katika [mwongozo wa Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya two forest root domains, pia ikitekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Trusti hizi zinaanzishwa na domain za Kerberos zisizo za Windows, zinazofuata [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na zinatumika kwa mazingira yanayohitaji kuingiliana na mifumo ya Kerberos nje ya ekosistimu ya Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust pia unaweza kuwa **transitive** (A inamuamini B, B inamuamini C, basi A inamuamini C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (pande zote zinaaminiana) au kama **one-way trust** (mmoja tu anamuamini mwingine).

### Attack Path

1. **Tafuta** uhusiano wa kuamini (trusting relationships)
2. Angalia ikiwa kuna **security principal** (user/group/computer) mwenye **ufikiaji** kwa rasilimali za **domain nyingine**, labda kupitia maingizo ya ACE au kwa kuwa katika makundi ya domain nyingine. Tafuta **uhusiano kati ya domain** (trust ilianzishwa kwa ajili ya hili labda).
1. kerberoast katika kesi hii inaweza kuwa chaguo nyingine.
3. **Chuna** akaunti ambazo zinaweza **kupitisha (pivot)** kupitia domain.

Wavamizi waliokuwa na ufikiaji wa rasilimali katika domain nyingine wanaweza kupitia njia tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwenye vikundi vya ndani kwenye mashine, kama kikundi cha “Administrators” kwenye server, kuwapatia udhibiti mkubwa wa mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa makundi ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii unategemea asili ya trust na upeo wa kundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kutajwa katika **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, kuwapa ufikiaji wa rasilimali maalum. Kwa wale wanaotaka kujifunza kwa undani zaidi jinsi ACLs, DACLs, na ACEs zinavyofanya kazi, whitepaper iliyoitwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali muhimu.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kupata foreign security principals katika domain. Hawa watakuwa watumiaji/makundi kutoka **domain/forest ya nje**.

Hii unaweza kuionyesha kwa **Bloodhound** au kutumia powerview:
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
> Unaweza kubaini ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Pata escalation kama Enterprise admin kwenye child/parent domain kwa kutumia uaminifu vibaya kupitia SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Ni muhimu kuelewa jinsi Configuration Naming Context (NC) inaweza kutumiwa mbaya. The Configuration NC serves as a central repository for configuration data across a forest in Active Directory (AD) environments. Hii data inaripikiwa kwa kila Domain Controller (DC) ndani ya msitu, ambapo DC zinazoweza kuandikwa zina nakala inayoweza kuandikwa ya Configuration NC. Ili kutumia hili, lazima uwe na **SYSTEM privileges on a DC**, afadhali child DC.

**Link GPO to root DC site**

Sites container ya Configuration NC inajumuisha taarifa kuhusu site za kompyuta zote zilizojiunga na domain ndani ya AD forest. Kwa kufanya kazi ukiwa na SYSTEM privileges on any DC, wadukuzi wanaweza link GPOs kwa root DC sites. Hatua hii inaweza kuathiri root domain kwa kurekebisha policies zinazotumika kwa sites hizi.

Kwa taarifa za kina, unaweza kusoma utafiti kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia ya kushambuliza ni kulenga gMSAs zilizo na haki za juu ndani ya domain. KDS Root key, muhimu kwa kuhesabu nywila za gMSAs, imehifadhiwa ndani ya Configuration NC. Ukiwa na SYSTEM privileges kwenye DC yoyote, inawezekana kufikia KDS Root key na kuhesabu nywila za gMSA yoyote katika msitu.

Uchambuzi wa kina na mwongozo wa hatua kwa hatua upo katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Shambulio la ziada la delegated MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Mbinu hii inahitaji subira, kusubiri uundaji wa vitu vipya vilivyo na haki za juu vya AD. Ukiwa na SYSTEM privileges, mdukuzi anaweza kubadilisha AD Schema ili kumpa mtumiaji yeyote udhibiti kamili juu ya classes zote. Hii inaweza kusababisha upatikanaji usioidhinishwa na udhibiti wa vitu vipya vya AD.

Maelezo zaidi yanaweza kupatikana katika [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

The ADCS ESC5 vulnerability inalenga kudhibiti vitu vya Public Key Infrastructure (PKI) ili kuunda template ya cheti inayowezesha authentication kama mtumiaji yeyote katika msitu. Kwa kuwa vitu vya PKI viko katika Configuration NC, kuharibu writable child DC kunaruhusu utekelezaji wa ESC5 attacks.

Maelezo zaidi yanaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira yasiyokuwa na ADCS, mdukuzi anaweza kuweka vipengele vinavyohitajika, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika senario hii **domain yako imeaminika** na moja ya nje ikikupa **idhinisho zisizobainishwa** juu yake. Utahitaji kubaini **ni principals gani wa domain yako wana ufikiaji gani juu ya domain ya nje** na kisha kujaribu ku-exploit:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domain ya Msitu wa Nje - Mwelekeo Mmoja (Outbound)
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
Katika tukio hili **domain yako** inampa **mhusika** kutoka kwa **domain tofauti** baadhi ya **idhinishwa**.

Hata hivyo, wakati **domain moja inapoaminwa** na domain inayomwamini, domain iliyokubaliwa **huunda mtumiaji** mwenye **jina linaloweza kutabiriwa** ambaye anatumia kama **nenosiri nenosiri la kuaminika**. Hii ina maana kwamba inawezekana **kupata akaunti kutoka kwa domain inayomwamini ili kuingia ndani ya domain iliyokubaliwa** kuirudisha na kujaribu kuinua idhini zaidi:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuathiri domain iliyokubaliwa ni kupata [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa kwa **mwelekeo wa kinyume** wa kuaminiana kwa domain (ambayo si ya kawaida).

Njia nyingine ya kuathiri domain iliyokubaliwa ni kusubiri kwenye mashine ambapo **mtumiaji kutoka domain iliyokubaliwa anaweza kufikia** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code katika mchakato wa kikao cha RDP na **kupata domain ya asili ya mwathirika** kutoka huko.\ Zaidi ya hayo, ikiwa **mwathirika ameunganisha diski yake kuu**, kutoka mchakato wa **kikao cha RDP** mshambuliaji anaweza kuhifadhi **backdoors** katika **folda ya kuanzisha ya diski kuu**. Mbinu hii inajulikana kama **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya kuaminiana kwa domain

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya SID history kwenye imani za forest inaathiriwa na SID Filtering, ambayo imewezeshwa kama chaguo-msingi kwa imani zote za inter-forest. Hii inatokana na dhana kwamba imani za intra-forest ni salama, ambapo forest, badala ya domain, huzingatiwa kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna upungufu: SID Filtering inaweza kuvuruga programu na upatikanaji wa watumiaji, na kusababisha kuzimwa kwake mara kwa mara.

### **Selective Authentication:**

- Kwa imani za inter-forest, kutumia Selective Authentication kunahakikisha kwamba watumiaji kutoka misitu miwili hawathibitishwa moja kwa moja. Badala yake, ruhusa wazi zinahitajika ili watumiaji wawekeze katika domains na server ndani ya domain au forest inayomwamini.
- Ni muhimu kutambua kwamba hatua hizi hazitulinde dhidi ya unyonyaji wa Configuration Naming Context (NC) inayoweza kuandikwa au mashambulizi dhidi ya akaunti ya trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Uorodheshaji wa LDAP upande wa implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` hugeuza majina mafupi/njia za OU kuwa DNs kamili na kuzitoa (dump) vitu vinavyolingana.
- `get-object`, `get-attribute`, and `get-domaininfo` huvuta sifa zote (ikiwa ni pamoja na security descriptors) pamoja na metadata ya forest/domain kutoka `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` zinaonyesha roasting candidates, mipangilio ya delegation, na descriptor zilizopo za [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) moja kwa moja kutoka LDAP.
- `get-acl` and `get-writable --detailed` huchanganua DACL ili kuorodhesha trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), na urithi, zikitoa malengo ya haraka kwa ajili ya kuinua mamlaka kupitia ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP primiti za uandishi kwa kuinua na kudumu

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) huruhusu mwendeshaji kuweka principals mpya au akaunti za mashine mahali popote haki za OU zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` hupora walengwa moja kwa moja mara tu haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` zinaweza kutafsiri WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa reset za nywila, udhibiti wa uanachama wa group, au haki za DCSync bila kuacha artifacts za PowerShell/ADSI. Vipengele vya `remove-*` vinakusanya ACE zilizowekwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hufanya mara moja mtumiaji aliyodhulumiwa kuwa Kerberoastable; `add-asreproastable` (UAC toggle) humalizia kuwa kwa AS-REP roasting bila kugusa nywila.
- Macros za delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) hurudisha `msDS-AllowedToDelegateTo`, UAC flags, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwa beacon, kuwezesha njia za mashambulio za constrained/unconstrained/RBCD na kuondoa haja ya PowerShell ya mbali au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` huingiza SIDs zenye heshima katika historia ya SID ya principal iliyodhibitiwa (ona [SID-History Injection](sid-history-injection.md)), ikitoa urithi wa upatikanaji kwa njama kwa njia fiche kabisa kwa LDAP/LDAPS.
- `move-object` hubadilisha DN/OU za kompyuta au watumiaji, ikimuruhusu mshambuliaji kuvuta mali ndani ya OUs ambazo haki za deligeshini tayari zipo kabla ya kutumika `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zilizofungwa kwa wigo (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, n.k.) zinaruhusu kurejesha haraka baada ya mwendeshaji kukusanya nywila au kudumisha upatikanaji, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Baadhi ya Ulinzi wa Msingi

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Hatua za Kinga kwa Ulinzi wa Nywila**

- **Domain Admins Restrictions**: Inapendekezwa kwamba Domain Admins waombolezwe kuingia tu kwenye Domain Controllers, kuepuka matumizi yao kwenye hosts nyingine.
- **Service Account Privileges**: Huduma zisifanywe kwa kutumia haki za Domain Admin (DA) ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji haki za DA, muda wao uwekewe kikomo. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Kutekeleza Mbinu za Ulaghai (Deception)**

- Kutekeleza deception kunahusisha kuweka mtego, kama watumiaji au kompyuta za kuiga, zenye sifa kama nywila ambazo hazitoweke au zimeorodheshwa kama Trusted for Delegation. Njia ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye makundi yenye mamlaka kubwa.
- Mfano wa vitendo unahusisha kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi kuhusu kutekeleza mbinu za deception zinapatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Ulaghai**

- **Kwa Vitu vya Mtumiaji**: Viashiria vinavyoshangaza ni pamoja na ObjectSID isiyo ya kawaida, kuingia kwa mara chache (infrequent logons), tarehe za uundaji, na idadi ndogo ya misimbo iliyokosewa (bad password counts).
- **Viashiria vya Jumla**: Kulinganisha sifa za vitu vinavyoweza kuwa decoy na zile za vitu halisi kunaweza kufichua ukosefu wa ulinganifu. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia katika kubaini deception hiyo.

### **Kupita Mifumo ya Ugunduzi**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka uorodheshaji wa session kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia funguo za **aes** kwa uundaji wa tiketi husaidia kuepuka utambuzi kwa kutodowngrade kwenda NTLM.
- **DCSync Attacks**: Kutekeleza kutoka kwa kifaa kisicho Domain Controller ili kuepuka utambuzi wa ATA inapendekezwa, kwani utekelezaji wa moja kwa moja kutoka Domain Controller utakasesha onyo.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
