# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Onlangse Windows builds het **SMB client support vir alternative TCP ports** ingestel. Daardie funksie kan misbruik word om **local NTLM authentication** in ’n **SYSTEM local privilege escalation** te omskep wanneer die aanvaller kan:

1. ’n SMB connection oopmaak na ’n attacker-controlled listener op ’n **non-445 port**
2. Daardie TCP connection lewendig hou
3. ’n **privileged local client** dwing om dieselfde **SMB share path** te gebruik
4. Die gevolglike **local NTLM authentication** terug relay na die masjien se regte SMB service

Dit is die primitive agter **CVE-2026-24294**, gepatch in **March 2026**.

## Why it works

Die ouer CMTI / serialized-SPN reflection truuk word hier behandel:

{{#ref}}
../ntlm/README.md
{{#endref}}

Hierdie nuwer variant het nie ’n marshalled hostname nodig nie. In plaas daarvan misbruik dit twee SMB client behaviours:

- **Alternative port support** op **Windows 11 24H2** en **Windows Server 2025**, blootgestel aan gebruikers met `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, waar multiple authenticated sessions op dieselfde TCP connection kan ry

Dit beteken ’n low-privileged user kan eers ’n TCP connection van die SMB client na ’n attacker SMB server op ’n hoë port skep, en dan ’n privileged service dwing om die **exact same UNC path** te gebruik. As Windows besluit om die bestaande TCP connection te hergebruik, word die privileged NTLM exchange oor die attacker-controlled transport gestuur en kan dit na die local SMB server relay word.

## Preconditions

- Target ondersteun SMB alternative ports:
- **Windows 11 24H2** of later
- **Windows Server 2025** of later
- Die attacker kan ’n local of remote SMB server op ’n gekose hoë port laat loop
- Die attacker kan ’n privileged service dwing om ’n UNC path te gebruik
- Die privileged authentication moet **NTLM local authentication** wees
- Die target moet relayable wees:
- Synacktiv het gerapporteer dat dit by verstek op **Windows Server 2025** gewerk het
- Hulle chain het **nie** op **Windows 11 24H2** gewerk nie omdat outbound SMB signing daar by verstek afgedwing word

## Userland and internals

Van die command line af lyk die feature eenvoudig:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmaties gebruik die kliënt `WNetAddConnection4W` met ongedokumenteerde `lpUseOptions` data. Die relevante opsie is `TraP` (transport parameters), wat uiteindelik die kernel SMB kliënt bereik via ’n FSCTL en deur `mrxsmb` ontleed word.

Belangrike praktiese notas:

- **UNC-sintaks het steeds geen poortveld nie**
- **`net use` is per-logon-session**
- Die bypass werk steeds omdat **die TCP-verbinding en die SMB-sessie aparte objekte is**
- Die **dieselfde share path** hergebruik is verpligtend as die exploit daarvan afhang dat die SMB kliënt die voorheen geskepte TCP-verbinding hergebruik

## Exploitation flow

### 1. Skep die aanvaller-beheerde SMB transport

Laat loop ’n SMB server op ’n hoë poort en maak Windows aan dit koppel:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Die bediener kan enige geloofsbriewe-paar aanvaar wat jy beheer, byvoorbeeld `user:user`. Die doel van hierdie stap is nog nie privilege escalation nie, net om die Windows SMB client te laat oopmaak en 'n herbruikbare TCP connection na jou listener te behou.

### 2. Dwing 'n bevoorregte diens na dieselfde UNC pad

Gebruik 'n coercion primitive soos **PetitPotam** teen dieselfde `\\192.168.56.3\share` pad. As die gedwonge client bevoorreg is en die teikennaam lokaal is (`localhost` of 'n plaaslike IP/host), voer Windows **NTLM local authentication** uit.

Omdat die TCP connection hergebruik word, gaan daardie bevoorregte NTLM exchange na die attacker SMB service in plaas daarvan om direk na die regte local SMB server te gaan.

### 3. Relay die bevoorregte authentication terug na local SMB

Die attacker-controlled SMB service stuur die bevoorregte NTLM exchange aan `ntlmrelayx.py` deur, wat dit na die masjien se werklike SMB listener relay en 'n sessie as `NT AUTHORITY\SYSTEM` verkry.

Tipiese tooling uit die publieke writeup:

- `smbserver.py` op 'n custom port om die bevoorregte auth oor die hergebruikte TCP connection te ontvang
- `ntlmrelayx.py` om die vasgelegde NTLM na local SMB te relay
- `PetitPotam.exe` of 'n ander coercion primitive om die bevoorregte authentication af te dwing

## Operator notes

- Dit is 'n **local privilege escalation** tegniek, nie 'n generiese remote relay truuk nie
- Die attacker-controlled SMB service moet die bevoorregte authentication op dieselfde **same TCP connection** hanteer wat oorspronklik vir die share mount gebruik is
- As die gedwonge toegang 'n **ander share path** tref, kan Windows 'n ander connection vestig en die chain breek
- SMB signing requirements kan die relay doodmaak, selfs wanneer die arbitrary-port stap werk
- As jy net Kerberos materiaal het of nie local NTLM kan afdwing nie, is hierdie presiese variant nie genoeg nie

## Detection and hardening

- Patch **CVE-2026-24294** vanaf **March 2026 Patch Tuesday**
- Hou dop vir `net use` of `New-SmbMapping` wat **non-default SMB ports** gebruik
- Stel alerts op ongewone outbound SMB vanaf workstations of servers na **high TCP ports**
- Hersien coercion opportunities soos **EFSRPC / PetitPotam-style** triggers
- Dwing SMB signing af waar moontlik; Synacktiv merk spesifiek op dat dit hulle relay op Windows 11 24H2 geblok het

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
