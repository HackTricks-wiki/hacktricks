# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** inatoa teknolojia ya msingi, ikiruhusu **wasimamizi wa mtandao** kuunda na kusimamia kwa ufanisi **doma**, **watumiaji**, na **vitu** ndani ya mtandao. Imeundwa ili kupanuka, ikisaidia kuandaa idadi kubwa ya watumiaji katika **makundi** na **subgroups** yanayoweza kudhibitiwa, huku ikidhibiti **haki za ufikiaji** katika ngazi mbalimbali.

Muundo wa **Active Directory** unajumuisha tabaka tatu kuu: **doma**, **miti**, na **misitu**. **Doma** inajumuisha mkusanyiko wa vitu, kama **watumiaji** au **vifaa**, vinavyoshiriki hifadhidata ya kawaida. **Miti** ni makundi ya hizi doma zilizounganishwa na muundo wa pamoja, na **msitu** unawakilisha mkusanyiko wa miti kadhaa, zilizounganishwa kupitia **uhusiano wa kuaminiana**, zikiforma tabaka la juu zaidi la muundo wa shirika. Haki maalum za **ufikiaji** na **mawasiliano** zinaweza kutolewa katika kila moja ya hizi ngazi.

Mifano muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Inahifadhi taarifa zote zinazohusiana na vitu vya Active Directory.
2. **Object** – Inamaanisha viumbe ndani ya directory, ikiwa ni pamoja na **watumiaji**, **makundi**, au **folda za pamoja**.
3. **Domain** – Inatumika kama chombo cha vitu vya directory, ikiwa na uwezo wa doma nyingi kuishi pamoja ndani ya **msitu**, kila moja ikihifadhi mkusanyiko wake wa vitu.
4. **Tree** – Kundi la doma zinazoshiriki domain ya mzizi wa pamoja.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kinachojumuisha miti kadhaa zikiwa na **uaminifu** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi zinajumuisha:

1. **Domain Services** – Inakusanya uhifadhi wa data na kusimamia mwingiliano kati ya **watumiaji** na **doma**, ikiwa ni pamoja na **uthibitishaji** na **utafutaji**.
2. **Certificate Services** – Inasimamia uundaji, usambazaji, na usimamizi wa **vyeti vya dijitali** salama.
3. **Lightweight Directory Services** – Inasaidia programu zinazotumia directory kupitia **protokali ya LDAP**.
4. **Directory Federation Services** – Inatoa uwezo wa **kuingia mara moja** kuthibitisha watumiaji katika programu nyingi za wavuti katika kikao kimoja.
5. **Rights Management** – Inasaidia kulinda mali ya hakimiliki kwa kudhibiti usambazaji na matumizi yake yasiyoidhinishwa.
6. **DNS Service** – Muhimu kwa kutatua **majina ya doma**.

Kwa maelezo zaidi, angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **kushambulia AD** unahitaji **kuelewa** vizuri mchakato wa **uthibitishaji wa Kerberos**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) kupata muonekano wa haraka wa amri ambazo unaweza kukimbia ili kuhesabu/kutumia AD.

## Recon Active Directory (No creds/sessions)

Ikiwa una ufikiaji tu wa mazingira ya AD lakini huna akreditivu/sessions unaweza:

- **Pentest mtandao:**
- Scan mtandao, pata mashine na bandari wazi na jaribu **kutumia udhaifu** au **kuchota akreditivu** kutoka kwao (kwa mfano, [printa zinaweza kuwa malengo ya kuvutia sana](ad-information-in-printers.md)).
- Kuangalia DNS kunaweza kutoa taarifa kuhusu seva muhimu katika domain kama wavuti, printa, sehemu, vpn, media, nk.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata maelezo zaidi kuhusu jinsi ya kufanya hivi.
- **Angalia ufikiaji wa null na Guest kwenye huduma za smb** (hii haitafanya kazi kwenye toleo la kisasa la Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Mwongozo wa kina juu ya jinsi ya kuhesabu seva ya SMB unaweza kupatikana hapa:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Hesabu Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Mwongozo wa kina juu ya jinsi ya kuhesabu LDAP unaweza kupatikana hapa (lipa **kipaumbele maalum kwa ufikiaji wa siri**):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison mtandao**
- Kusanya akreditivu [**ukijifanya huduma kwa Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Fikia mwenyeji kwa [**kudhulumu shambulio la relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya akreditivu **ukifichua** [**huduma za UPnP za uongo na evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
- Toa majina ya watumiaji/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, huduma (hasa wavuti) ndani ya mazingira ya domain na pia kutoka kwa yaliyopo hadharani.
- Ikiwa unapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu mifumo tofauti ya **majina ya watumiaji AD** (**[**soma hii**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Mifumo ya kawaida ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _za nasibu na nambari 3 za nasibu_ (abc123).
- Zana:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) kurasa.
- **Kerbrute enum**: Wakati **jina la mtumiaji lisilo sahihi linapohitajika** seva itajibu kwa kutumia **kodi ya kosa la Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ikituruhusu kubaini kwamba jina la mtumiaji halikuwa sahihi. **Majina sahihi ya watumiaji** yatatoa ama **TGT katika jibu la AS-REP** au kosa _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kwamba mtumiaji anahitajika kufanya uthibitishaji wa awali.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
- **OWA (Outlook Web Access) Server**

Ikiwa umepata moja ya seva hizi katika mtandao unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia chombo [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Unaweza kupata orodha za majina ya watumiaji katika [**hii github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* na hii nyingine ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Hata hivyo, unapaswa kuwa na **jina la watu wanaofanya kazi katika kampuni** kutoka hatua ya recon ambayo unapaswa kuwa umefanya kabla ya hii. Ukiwa na jina na jina la ukoo unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuunda majina ya watumiaji halali yanayoweza kuwa.

### Kujua jina moja au kadhaa la watumiaji

Sawa, kwa hivyo unajua tayari una jina halali la mtumiaji lakini hakuna nywila... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** sifa _DONT_REQ_PREAUTH_ unaweza **kuomba ujumbe wa AS_REP** kwa mtumiaji huyo ambao utakuwa na data fulani iliyosimbwa kwa derivation ya nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Hebu jaribu nywila **za kawaida zaidi** na kila mmoja wa watumiaji waliogunduliwa, labda mtumiaji fulani anatumia nywila mbaya (kumbuka sera ya nywila!).
- Kumbuka kwamba unaweza pia **spray OWA servers** kujaribu kupata ufikiaji wa seva za barua za watumiaji.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Unaweza kuwa na uwezo wa **kupata** baadhi ya changamoto **hashes** ili kuvunja **kuambukiza** baadhi ya protokali za **mtandao**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTML Relay

Ikiwa umeweza kuhesabu active directory utakuwa na **barua pepe zaidi na ufahamu bora wa mtandao**. Unaweza kuwa na uwezo wa kulazimisha NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* kupata ufikiaji wa mazingira ya AD.

### Kuiba NTLM Creds

Ikiwa unaweza **kufikia kompyuta nyingine au sehemu** na **mtumiaji wa null au mgeni** unaweza **kweka faili** (kama faili ya SCF) ambayo ikiwa kwa namna fulani itafikiwa it **trigger an NTML authentication against you** ili uweze **kuiba** **NTLM challenge** ili kuivunja:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Kuorodhesha Active Directory KWA nywila/sessheni

Kwa hatua hii unahitaji kuwa **umevunjika nywila au sessheni ya akaunti halali ya domain.** Ikiwa una nywila halali au shell kama mtumiaji wa domain, **unapaswa kukumbuka kwamba chaguzi zilizotolewa hapo awali bado ni chaguzi za kuvunja watumiaji wengine**.

Kabla ya kuanza kuorodhesha kwa uthibitisho unapaswa kujua ni nini **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Kuorodhesha

Kuwa na akaunti iliyovunjika ni **hatua kubwa ya kuanza kuvunja domain nzima**, kwa sababu utaweza kuanza **Kuorodhesha Active Directory:**

Kuhusu [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji anayeweza kuwa hatarini, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu nywila ya akaunti iliyovunjika, nywila tupu na nywila mpya zinazowezekana.

- Unaweza kutumia [**CMD kufanya recon ya msingi**](../basic-cmd-for-pentesters.md#domain-info)
- Unaweza pia kutumia [**powershell kwa recon**](../basic-powershell-for-pentesters/) ambayo itakuwa ya siri zaidi
- Unaweza pia [**kutumia powerview**](../basic-powershell-for-pentesters/powerview.md) kutoa taarifa za kina zaidi
- Zana nyingine nzuri kwa ajili ya recon katika active directory ni [**BloodHound**](bloodhound.md). Si **ya siri sana** (kulingana na mbinu za ukusanyaji unazotumia), lakini **ikiwa hujali** kuhusu hilo, unapaswa kujaribu kabisa. Pata mahali ambapo watumiaji wanaweza RDP, pata njia za makundi mengine, nk.
- **Zana nyingine za kuorodhesha za AD za kiotomatiki ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Rekodi za DNS za AD**](ad-dns-records.md) kwani zinaweza kuwa na taarifa za kuvutia.
- **Zana yenye GUI** ambayo unaweza kutumia kuorodhesha directory ni **AdExplorer.exe** kutoka **SysInternal** Suite.
- Unaweza pia kutafuta katika database ya LDAP kwa **ldapsearch** kutafuta nywila katika maeneo _userPassword_ & _unixUserPassword_, au hata kwa _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
- Ikiwa unatumia **Linux**, unaweza pia kuorodhesha domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
- Unaweza pia kujaribu zana za kiotomatiki kama:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Kutoa majina yote ya watumiaji wa domain**

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Kuorodhesha inaonekana ndogo hii ndiyo sehemu muhimu zaidi ya yote. Fikia viungo (hasa ile ya cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuorodhesha domain na fanya mazoezi hadi ujisikie vizuri. Wakati wa tathmini, hii itakuwa wakati muhimu wa kupata njia yako hadi DA au kuamua kwamba hakuna kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na huduma zinazohusiana na akaunti za watumiaji na kuvunja usimbaji wao—ambao unategemea nywila za watumiaji—**offline**.

Zaidi kuhusu hii katika:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, nk)

Mara tu unapokuwa umepata baadhi ya nywila unaweza kuangalia ikiwa una ufikiaji wa **mashine** yoyote. Kwa jambo hilo, unaweza kutumia **CrackMapExec** kujaribu kuungana kwenye seva kadhaa kwa kutumia protokali tofauti, kulingana na skana zako za port.

### Local Privilege Escalation

Ikiwa umevunjika nywila au sessheni kama mtumiaji wa kawaida wa domain na una **ufikiaji** na mtumiaji huyu kwa **mashine yoyote katika domain** unapaswa kujaribu kupata njia yako ya **kuinua mamlaka kwa ndani na kutafuta nywila**. Hii ni kwa sababu ni tu kwa mamlaka ya msimamizi wa ndani utaweza **dump hashes za watumiaji wengine** katika kumbukumbu (LSASS) na kwa ndani (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**kuinua mamlaka ya ndani katika Windows**](../windows-local-privilege-escalation/) na [**orodha ya ukaguzi**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **ngumu sana** kwamba utapata **tickets** katika mtumiaji wa sasa **ukikupa ruhusa ya kufikia** rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Ikiwa umeweza kuhesabu active directory utakuwa na **barua pepe zaidi na ufahamu bora wa mtandao**. Unaweza kuwa na uwezo wa kulazimisha NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Angalia Creds katika Computer Shares**

Sasa kwamba una baadhi ya akidi za msingi unapaswa kuangalia kama unaweza **kupata** faili zozote **za kuvutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mikono lakini ni kazi ya kuchosha na ya kurudiwa (na zaidi ikiwa unapata mamia ya hati unahitaji kuangalia).

[**Fuata kiungo hiki kujifunza kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kufikia PCs nyingine au shares** unaweza **kweka faili** (kama faili la SCF) ambayo ikiwa kwa namna fulani inafikiwa it **itazindua uthibitisho wa NTML dhidi yako** ili uweze **kuiba** **changamoto ya NTLM** ili kuifungua:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ushahidi huu uliruhusu mtumiaji yeyote aliyeidhinishwa **kuathiri kidhibiti cha eneo**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zifuatazo mtumiaji wa kawaida wa eneo si wa kutosha, unahitaji baadhi ya haki/akidi maalum ili kutekeleza mashambulizi haya.**

### Hash extraction

Tuna matumaini umeweza **kuathiri akaunti ya msimamizi wa ndani** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ikiwa ni pamoja na relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [kuinua haki kwa ndani](../windows-local-privilege-escalation/).\
Kisha, ni wakati wa kutupa hash zote kwenye kumbukumbu na ndani.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapo kuwa na hash ya mtumiaji**, unaweza kuitumia ili **kujifanya** kuwa yeye.\
Unahitaji kutumia **chombo** ambacho kitafanya **uthibitisho wa NTLM kwa kutumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hiyo **hash** ndani ya **LSASS**, hivyo wakati wowote **uthibitisho wa NTLM unafanywa**, hiyo **hash itatumika.** Chaguo la mwisho ndilo ambalo mimikatz hufanya.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulizi hili linakusudia **kutumia hash ya mtumiaji wa NTLM kuomba tiketi za Kerberos**, kama mbadala wa Pass The Hash ya kawaida juu ya itifaki ya NTLM. Hivyo, hii inaweza kuwa hasa **faida katika mitandao ambapo itifaki ya NTLM imezimwa** na tu **Kerberos inaruhusiwa** kama itifaki ya uthibitisho.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Katika mbinu ya shambulizi ya **Pass The Ticket (PTT)**, washambuliaji **wanaiba tiketi ya uthibitisho ya mtumiaji** badala ya nenosiri lao au thamani za hash. Tiketi hii iliyokuwa imeibiwa inatumika kisha **kujifanya kuwa mtumiaji**, ikipata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **nenosiri** la **msimamizi wa ndani** unapaswa kujaribu **kuingia kwa ndani** kwenye **PCs** nyingine kwa kutumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hii ni **kelele** na **LAPS** itapunguza.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana mamlaka ya **kufikia mifano ya MSSQL**, anaweza kuwa na uwezo wa kuitumia **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inafanya kazi kama SA), **kuiba** NetNTLM **hash** au hata kufanya **shambulio la relay**.\
Pia, ikiwa mfano wa MSSQL unakubaliwa (kiungo cha database) na mfano mwingine wa MSSQL. Ikiwa mtumiaji ana mamlaka juu ya database iliyoaminika, atakuwa na uwezo wa **kutumia uhusiano wa kuaminiana kutekeleza maswali pia kwenye mfano mwingine**. Hizi uhusiano zinaweza kuunganishwa na wakati fulani mtumiaji anaweza kupata database iliyo na makosa ambapo anaweza kutekeleza amri.\
**Viungo kati ya databases vinafanya kazi hata katika uhusiano wa msitu.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Unconstrained Delegation

Ikiwa unapata kitu chochote cha Kompyuta chenye sifa [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una mamlaka ya eneo kwenye kompyuta, utaweza kutoa TGTs kutoka kwenye kumbukumbu ya kila mtumiaji anayeingia kwenye kompyuta.\
Hivyo, ikiwa **Msimamizi wa Eneo anaingia kwenye kompyuta**, utaweza kutoa TGT yake na kumwakilisha kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa uhamasishaji wa kizuizi unaweza hata **kuathiri kiotomatiki Server ya Print** (tunatumai itakuwa DC).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta inaruhusiwa kwa "Constrained Delegation" itakuwa na uwezo wa **kumwakilisha mtumiaji yeyote kufikia huduma fulani kwenye kompyuta**.\
Kisha, ikiwa **utavunja hash** ya mtumiaji/hii kompyuta utaweza **kumwakilisha mtumiaji yeyote** (hata wasimamizi wa eneo) kufikia huduma fulani.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na **WRITE** mamlaka kwenye kitu cha Active Directory cha kompyuta ya mbali kunaruhusu kupata utekelezaji wa msimbo wenye **mamlaka ya juu**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### ACLs Abuse

Mtumiaji aliyeathiriwa anaweza kuwa na **mamlaka ya kuvutia juu ya baadhi ya vitu vya eneo** ambavyo vinaweza kukuruhusu **kuhamasisha** kwa upande/**kuinua** mamlaka.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua **Huduma ya Spool inayosikiliza** ndani ya eneo inaweza **kutumika vibaya** ili **kupata akidi mpya** na **kuinua mamlaka**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** **wanapata** mashine **iliyoathiriwa**, inawezekana **kukusanya akidi kutoka kwenye kumbukumbu** na hata **kuingiza beacons katika michakato yao** ili kuwawakilisha.\
Kawaida watumiaji wataingia kwenye mfumo kupitia RDP, hivyo hapa kuna jinsi ya kufanya mashambulizi kadhaa juu ya vikao vya RDP vya wahusika wengine:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** inatoa mfumo wa kusimamia **neno la siri la Msimamizi wa ndani** kwenye kompyuta zilizounganishwa na eneo, kuhakikisha kuwa ni **ya nasibu**, ya kipekee, na mara kwa mara **inabadilishwa**. Maneno haya ya siri yanahifadhiwa katika Active Directory na ufikiaji unadhibitiwa kupitia ACLs kwa watumiaji walioidhinishwa tu. Kwa ruhusa ya kutosha ya kufikia maneno haya ya siri, kuhamasisha kwa kompyuta nyingine kunakuwa na uwezekano.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya vyeti** kutoka kwenye mashine iliyoharibiwa inaweza kuwa njia ya kuinua mamlaka ndani ya mazingira:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **mifano ya hatari** imewekwa inawezekana kuzitumia vibaya ili kuinua mamlaka:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara tu unapopata **Msimamizi wa Eneo** au hata bora **Msimamizi wa Biashara**, unaweza **kutoa** **database ya eneo**: _ntds.dit_.

[**Taarifa zaidi kuhusu shambulio la DCSync inaweza kupatikana hapa**](dcsync.md).

[**Taarifa zaidi kuhusu jinsi ya kuiba NTDS.dit inaweza kupatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya mbinu zilizozungumziwa hapo awali zinaweza kutumika kwa kudumu.\
Kwa mfano unaweza:

- Kufanya watumiaji kuwa hatarini kwa [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kufanya watumiaji kuwa hatarini kwa [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Kutoa [**DCSync**](./#dcsync) mamlaka kwa mtumiaji

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Shambulio la Silver Ticket** linaunda **tiketi halali ya Huduma ya Kutoa Tiketi (TGS)** kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya akaunti ya PC**). Njia hii inatumika ili **kufikia mamlaka ya huduma**.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Shambulio la Golden Ticket** linahusisha mshambuliaji kupata ufikiaji wa **NTLM hash ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu inatumika kusaini **Tiketi za Kutoa Tiketi (TGTs)**, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mshambuliaji anapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote anayotaka (shambulio la tiketi ya fedha).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama tiketi za dhahabu zilizoforgiwa kwa njia ambayo **inasababisha kupita mifumo ya kawaida ya kugundua tiketi za dhahabu.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na vyeti vya akaunti au kuwa na uwezo wa kuviomba** ni njia nzuri sana ya kuweza kudumu katika akaunti za watumiaji (hata kama anabadilisha nenosiri):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia vyeti pia kunawezekana kudumu kwa mamlaka ya juu ndani ya eneo:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kitu cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **makundi yenye mamlaka** (kama Wasimamizi wa Eneo na Wasimamizi wa Biashara) kwa kutumia **Orodha ya Udhibiti wa Ufikiaji (ACL)** ya kawaida kati ya makundi haya ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, kipengele hiki kinaweza kutumika vibaya; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder ili kutoa ufikiaji kamili kwa mtumiaji wa kawaida, mtumiaji huyo anapata udhibiti mkubwa juu ya makundi yote yenye mamlaka. Kipimo hiki cha usalama, kilichokusudiwa kulinda, kinaweza hivyo kurudi nyuma, kuruhusu ufikiaji usiofaa isipokuwa ufuatiliwe kwa karibu.

[**Taarifa zaidi kuhusu Kundi la AdminDSHolder hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Msimamizi wa Eneo (DC)**, akaunti ya **msimamizi wa ndani** inapatikana. Kwa kupata haki za usimamizi kwenye mashine kama hiyo, hash ya Msimamizi wa ndani inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hapo, mabadiliko ya rejista yanahitajika ili **kuwezesha matumizi ya nenosiri hili**, kuruhusu ufikiaji wa mbali kwa akaunti ya Msimamizi wa ndani.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kutoa** baadhi ya **mamlaka maalum** kwa **mtumiaji** juu ya baadhi ya vitu maalum vya eneo ambavyo vitamruhusu mtumiaji **kuinua mamlaka katika siku zijazo**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Maelezo ya usalama** yanatumika kuhifadhi **mamlaka** ambayo **kitu** kina **juu ya** **kitu**. Ikiwa unaweza tu **kufanya** **mabadiliko madogo** katika **maelezo ya usalama** ya kitu, unaweza kupata mamlaka ya kuvutia sana juu ya kitu hicho bila kuhitaji kuwa mwanachama wa kundi lenye mamlaka.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** katika kumbukumbu ili kuanzisha **neno la siri la ulimwengu**, linalotoa ufikiaji kwa akaunti zote za eneo.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Jifunze nini SSP (Mtoa Msaada wa Usalama) hapa.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kukamata** kwa **maandishi wazi** **akidi** zinazotumika kufikia mashine.\\

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Msimamizi mpya wa Eneo** katika AD na inautumia **kushinikiza sifa** (SIDHistory, SPNs...) kwenye vitu vilivyotajwa **bila** kuacha **kumbukumbu** kuhusu **mabadiliko**. Unahitaji ruhusa za DA na uwe ndani ya **domeni ya mzizi**.\
Kumbuka kwamba ikiwa utatumia data mbaya, kumbukumbu mbaya sana zitaonekana.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Kabla tulizungumzia jinsi ya kuinua mamlaka ikiwa una **ruhusa za kutosha kusoma maneno ya siri ya LAPS**. Hata hivyo, maneno haya ya siri yanaweza pia kutumika **kuhifadhi kudumu**.\
Angalia:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Msitu** kama mpaka wa usalama. Hii inamaanisha kwamba **kuharibu eneo moja kunaweza kusababisha msitu mzima kuharibiwa**.

### Basic Information

[**Uhusiano wa eneo**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mekanizma ya usalama inayowezesha mtumiaji kutoka kwenye **eneo** kufikia rasilimali katika **eneo** lingine. Kimsingi inaunda uhusiano kati ya mifumo ya uthibitishaji ya maeneo mawili, ikiruhusu uthibitishaji wa verifications kuhamasika bila shida. Wakati maeneo yanapoweka uhusiano wa kuaminiana, wanabadilishana na kuhifadhi funguo maalum ndani ya **Msimamizi wao wa Eneo (DCs)**, ambazo ni muhimu kwa uaminifu wa uhusiano huo.

Katika hali ya kawaida, ikiwa mtumiaji anataka kufikia huduma katika **eneo lililoaminika**, lazima kwanza aombe tiketi maalum inayojulikana kama **inter-realm TGT** kutoka DC ya eneo lake mwenyewe. TGT hii imefungwa kwa **funguo** iliyoshirikiwa ambayo maeneo yote mawili yamekubaliana. Mtumiaji kisha anawasilisha TGT hii kwa **DC ya eneo lililoaminika** ili kupata tiketi ya huduma (**TGS**). Baada ya uthibitishaji wa mafanikio wa inter-realm TGT na DC ya eneo lililoaminika, inatoa TGS, ikimpa mtumiaji ufikiaji wa huduma.

**Hatua**:

1. **Kompyuta ya mteja** katika **Eneo 1** inaanza mchakato kwa kutumia **NTLM hash** yake kuomba **Tiketi ya Kutoa Tiketi (TGT)** kutoka kwa **Msimamizi wake wa Eneo (DC1)**.
2. DC1 inatoa TGT mpya ikiwa mteja ameidhinishwa kwa mafanikio.
3. Mteja kisha anaomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Eneo 2**.
4. Inter-realm TGT imefungwa kwa **funguo ya kuaminiana** iliyoshirikiwa kati ya DC1 na DC2 kama sehemu ya uhusiano wa kuaminiana wa pande mbili.
5. Mteja anachukua inter-realm TGT kwa **Msimamizi wa Eneo 2 (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia funguo yake ya kuaminiana iliyoshirikiwa na, ikiwa ni halali, inatoa **Huduma ya Kutoa Tiketi (TGS)** kwa seva katika Eneo 2 ambayo mteja anataka kufikia.
7. Hatimaye, mteja anawasilisha TGS hii kwa seva, ambayo imefungwa kwa hash ya akaunti ya seva, ili kupata ufikiaji wa huduma katika Eneo 2.

### Different trusts

Ni muhimu kutambua kwamba **uaminifu unaweza kuwa wa njia 1 au njia 2**. Katika chaguo za njia 2, maeneo yote mawili yatakuwa na uaminifu kwa kila mmoja, lakini katika uhusiano wa **njia 1** moja ya maeneo itakuwa **ya kuaminika** na nyingine itakuwa **ya kuamini**. Katika kesi ya mwisho, **utaweza tu kufikia rasilimali ndani ya eneo linaloamini kutoka eneo lililoaminika**.

Ikiwa Eneo A linakubali Eneo B, A ni eneo linaloamini na B ni eneo lililoaminika. Zaidi ya hayo, katika **Eneo A**, hii itakuwa **Uaminifu wa Nje**; na katika **Eneo B**, hii itakuwa **Uaminifu wa Ndani**.

**Uhusiano tofauti wa kuamini**

- **Uhusiano wa Mzazi-Mwana**: Hii ni mipangilio ya kawaida ndani ya msitu mmoja, ambapo eneo la mtoto moja kwa moja lina uhusiano wa kuaminiana wa njia mbili na eneo lake la mzazi. Kimsingi, hii inamaanisha kwamba maombi ya uthibitishaji yanaweza kuhamasika bila shida kati ya mzazi na mtoto.
- **Uhusiano wa Msalaba**: Inajulikana kama "uaminifu wa mkato," hizi zimeanzishwa kati ya maeneo ya watoto ili kuharakisha michakato ya rufaa. Katika misitu ngumu, rufaa za uthibitishaji kawaida zinahitaji kusafiri hadi mzizi wa msitu na kisha kushuka hadi eneo lengwa. Kwa kuunda viungo vya msalaba, safari inakuwa fupi, ambayo ni faida hasa katika mazingira yaliyosambazwa kijiografia.
- **Uhusiano wa Nje**: Hizi zimeanzishwa kati ya maeneo tofauti, yasiyo na uhusiano na ni zisizo za njia. Kulingana na [nyaraka za Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), uhusiano wa nje ni muhimu kwa kufikia rasilimali katika eneo nje ya msitu wa sasa ambao haujaunganishwa na uhusiano wa msitu. Usalama unaboreshwa kupitia kuchuja SID na uhusiano wa nje.
- **Uhusiano wa Mti-Mzizi**: Hizi uhusiano zinaanzishwa moja kwa moja kati ya eneo la mzizi wa msitu na mti mpya ulioongezwa. Ingawa hazikutana mara nyingi, uhusiano wa mti-mzizi ni muhimu kwa kuongeza miti mipya ya eneo kwenye msitu, ikiruhusu kudumisha jina la kipekee la eneo na kuhakikisha uhamasishaji wa njia mbili. Taarifa zaidi zinaweza kupatikana katika [mwongozo wa Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Uhusiano wa Msitu**: Aina hii ya uaminifu ni uaminifu wa njia mbili kati ya maeneo mawili ya mzizi wa msitu, pia ikilazimisha kuchuja SID ili kuimarisha hatua za usalama.
- **Uhusiano wa MIT**: Hizi uhusiano zimeanzishwa na maeneo ya Kerberos yasiyo ya Windows, [RFC4120-inayokubalika](https://tools.ietf.org/html/rfc4120). Uhusiano wa MIT ni maalum zaidi na unalenga mazingira yanayohitaji ushirikiano na mifumo ya Kerberos nje ya mfumo wa Windows.

#### Tofauti nyingine katika **uhusiano wa kuamini**

- Uhusiano wa kuamini unaweza pia kuwa **wa njia** (A inakubali B, B inakubali C, kisha A inakubali C) au **usio wa njia**.
- Uhusiano wa kuamini unaweza kuwekwa kama **uaminifu wa pande mbili** (wote wanakubali kila mmoja) au kama **uaminifu wa njia moja** (moja tu kati yao inakubali mwingine).

### Attack Path

1. **Tathmini** uhusiano wa kuamini
2. Angalia ikiwa **kiongozi wa usalama** (mtumiaji/kundi/kompyuta) ana **ufikiaji** wa rasilimali za **eneo lingine**, labda kwa njia ya ACE entries au kwa kuwa katika makundi ya eneo lingine. Tafuta **uhusiano kati ya maeneo** (uaminifu ulianzishwa kwa hili labda).
1. kerberoast katika kesi hii inaweza kuwa chaguo lingine.
3. **Haribu** **akaunti** ambazo zinaweza **kuhamasisha** kupitia maeneo.
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
> [!WARNING]
> Kuna **funguo 2 za kuaminika**, moja kwa _Child --> Parent_ na nyingine kwa _Parent_ --> _Child_.\
> Unaweza kutumia ile inayotumika na eneo la sasa kwa:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Pandisha kama msimamizi wa Enterprise kwa eneo la mtoto/ mzazi kwa kutumia uaminifu na SID-History injection:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumika ni muhimu. Configuration NC inatumika kama hazina kuu ya data za usanidi katika msitu wa Active Directory (AD). Data hii inakopwa kwa kila Domain Controller (DC) ndani ya msitu, huku DC zinazoweza kuandikwa zikihifadhi nakala inayoweza kuandikwa ya Configuration NC. Ili kutumia hili, mtu lazima awe na **mamlaka ya SYSTEM kwenye DC**, bora iwe DC ya mtoto.

**Link GPO to root DC site**

Konteina ya Sites ya Configuration NC inajumuisha taarifa kuhusu tovuti za kompyuta zote zilizounganishwa na eneo ndani ya msitu wa AD. Kwa kufanya kazi na mamlaka ya SYSTEM kwenye DC yoyote, washambuliaji wanaweza kuunganisha GPOs kwenye tovuti za root DC. Kitendo hiki kinaweza kuhatarisha eneo la mzazi kwa kubadilisha sera zinazotumika kwenye tovuti hizi.

Kwa taarifa za kina, mtu anaweza kuchunguza utafiti kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia ya shambulio inahusisha kulenga gMSA zenye mamlaka ndani ya eneo. Funguo ya KDS Root, muhimu kwa kuhesabu nywila za gMSA, inahifadhiwa ndani ya Configuration NC. Kwa mamlaka ya SYSTEM kwenye DC yoyote, inawezekana kufikia funguo ya KDS Root na kuhesabu nywila za gMSA yoyote ndani ya msitu.

Uchambuzi wa kina unaweza kupatikana katika mjadala kuhusu [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Njia hii inahitaji uvumilivu, kusubiri kuundwa kwa vitu vipya vya AD vyenye mamlaka. Kwa mamlaka ya SYSTEM, mshambuliaji anaweza kubadilisha Schema ya AD ili kumpa mtumiaji yeyote udhibiti kamili juu ya makundi yote. Hii inaweza kusababisha ufikiaji usioidhinishwa na udhibiti wa vitu vipya vya AD vilivyoundwa.

Kusoma zaidi kunaweza kupatikana kwenye [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Ukatili wa ADCS ESC5 unalenga udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda kigezo cha cheti kinachowezesha uthibitisho kama mtumiaji yeyote ndani ya msitu. Kwa kuwa vitu vya PKI vinapatikana katika Configuration NC, kuhatarisha DC ya mtoto inayoweza kuandikwa kunaruhusu utekelezaji wa mashambulizi ya ESC5.

Maelezo zaidi kuhusu hili yanaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika hali zisizo na ADCS, mshambuliaji ana uwezo wa kuanzisha vipengele muhimu, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Katika hali hii **domeni yako inatambuliwa** na nyingine ya nje ikikupa **idhini zisizojulikana** juu yake. Utahitaji kutafuta **ni wakuu gani wa domeni yako wana ufikiaji gani juu ya domeni ya nje** na kisha jaribu kuifanyia kazi:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domeni ya Msitu wa Nje - Njia Moja (Nje)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Katika hali hii **domeni yako** in **amini** baadhi ya **mamlaka** kwa kiongozi kutoka **domeni tofauti**.

Hata hivyo, wakati **domeni inapoaminika** na domeni inayoamini, domeni iliyoaminika **inaunda mtumiaji** mwenye **jina linaloweza kutabiriwa** ambalo linatumia kama **nenosiri nenosiri lililoaminika**. Hii ina maana kwamba inawezekana **kufikia mtumiaji kutoka kwenye domeni inayoamini ili kuingia kwenye ile iliyoaminika** ili kuhesabu na kujaribu kupandisha mamlaka zaidi:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuathiri domeni iliyoaminika ni kutafuta [**kiungo cha SQL kilichoaminika**](abusing-ad-mssql.md#mssql-trusted-links) kilichoundwa katika **mwelekeo kinyume** cha uaminifu wa domeni (ambayo si ya kawaida sana).

Njia nyingine ya kuathiri domeni iliyoaminika ni kusubiri kwenye mashine ambapo **mtumiaji kutoka kwenye domeni iliyoaminika anaweza kufikia** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza msimbo katika mchakato wa kikao cha RDP na **kufikia domeni ya asili ya mwathirika** kutoka pale.\
Zaidi ya hayo, ikiwa **mwathirika ameunganisha diski yake ngumu**, kutoka kwenye mchakato wa **kikao cha RDP** mshambuliaji anaweza kuhifadhi **backdoors** kwenye **kabrasha la kuanzisha la diski ngumu**. Mbinu hii inaitwa **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya uaminifu wa domeni

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya historia ya SID katika uaminifu wa misitu inapunguziliwa mbali na SID Filtering, ambayo imewezeshwa kwa chaguo-msingi kwenye uaminifu wote wa kati ya misitu. Hii inategemea dhana kwamba uaminifu wa ndani ya misitu ni salama, ikizingatia msitu, badala ya domeni, kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna tatizo: filtering ya SID inaweza kuathiri programu na ufikiaji wa watumiaji, na kusababisha kuondolewa kwake mara kwa mara.

### **Uthibitishaji wa Chaguo:**

- Kwa uaminifu wa kati ya misitu, kutumia Uthibitishaji wa Chaguo kunahakikisha kwamba watumiaji kutoka kwenye misitu miwili hawathibitishwi moja kwa moja. Badala yake, ruhusa wazi zinahitajika kwa watumiaji kufikia domeni na seva ndani ya domeni au msitu unaoamini.
- Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya matumizi mabaya ya Muktadha wa Jina la Mkononi (NC) unaoweza kuandikwa au mashambulizi kwenye akaunti ya uaminifu.

[**Taarifa zaidi kuhusu uaminifu wa domeni katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity
{{#endref}}

## Ulinzi wa Jumla

[**Jifunze zaidi kuhusu jinsi ya kulinda hati hapa.**](../stealing-credentials/credentials-protections.md)\\

### **Hatua za Kijeshi za Ulinzi wa Hati**

- **Vikwazo vya Wasimamizi wa Domeni**: Inapendekezwa kwamba Wasimamizi wa Domeni wanapaswa kuruhusiwa kuingia tu kwenye Wasimamizi wa Domeni, kuepuka matumizi yao kwenye mwenyeji wengine.
- **Mamlaka ya Akaunti ya Huduma**: Huduma hazipaswi kuendeshwa kwa mamlaka ya Wasimamizi wa Domeni (DA) ili kudumisha usalama.
- **Kikomo cha Muda wa Mamlaka**: Kwa kazi zinazohitaji mamlaka ya DA, muda wao unapaswa kuwa mdogo. Hii inaweza kufanywa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Kutekeleza Mbinu za Udanganyifu**

- Kutekeleza udanganyifu kunahusisha kuweka mitego, kama vile watumiaji wa udanganyifu au kompyuta, zikiwa na sifa kama vile nenosiri ambazo hazitaisha au zimewekwa kama Zinazoaminika kwa Uwakilishi. Njia ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye vikundi vya mamlaka ya juu.
- Mfano wa vitendo unahusisha kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi kuhusu kutekeleza mbinu za udanganyifu yanaweza kupatikana kwenye [Deploy-Deception kwenye GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

- **Kwa Vitu vya Mtumiaji**: Viashiria vya kutatanisha ni pamoja na ObjectSID isiyo ya kawaida, kuingia mara chache, tarehe za uundaji, na idadi ndogo ya nenosiri mbaya.
- **Viashiria vya Jumla**: Kulinganisha sifa za vitu vya udanganyifu vinavyowezekana na zile za halali kunaweza kufichua kutokuelewana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia katika kutambua udanganyifu kama huo.

### **Kupita Mfumo wa Ugunduzi**

- **Kupita Ugunduzi wa Microsoft ATA**:
- **Uhesabuji wa Watumiaji**: Kuepuka uhesabuji wa kikao kwenye Wasimamizi wa Domeni ili kuzuia ugunduzi wa ATA.
- **Uigaji wa Tiketi**: Kutumia funguo za **aes** kwa ajili ya uundaji wa tiketi husaidia kuepuka ugunduzi kwa kutoshuka hadi NTLM.
- **Mashambulizi ya DCSync**: Kutekeleza kutoka kwa Wasimamizi wa Domeni sio pendekezo, kwani kutekeleza moja kwa moja kutoka kwa Wasimamizi wa Domeni kutasababisha arifa.

## Marejeleo

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
