# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Onlangse Windows builds het **SMB client support for alternative TCP ports** bekendgestel. Daardie funksie kan misbruik word om **local NTLM authentication** in ’n **SYSTEM local privilege escalation** te omskep wanneer die aanvaller kan:<sup>[[1]](#references)</sup>

1. ’n SMB-verbinding na ’n aanvaller-beheerde listener op ’n **non-445 port** oopmaak
2. Daardie TCP-verbinding aktief hou
3. ’n **privileged local client** dwing om toegang tot die **same SMB share path** te verkry
4. Die gevolglike **local NTLM authentication** terug na die masjien se werklike SMB-diens relay

Dit is die primitive agter **CVE-2026-24294**, wat in **March 2026** gepatch is.<sup>[[1]](#references)[[4]](#references)</sup>

## Waarom dit werk

Die ouer CMTI / serialized-SPN reflection trick word hier gedek:

{{#ref}}
../ntlm/README.md
{{#endref}}

Hierdie nuwer variant het nie ’n marshalled hostname nodig nie. In plaas daarvan misbruik dit twee SMB client behaviours:<sup>[[1]](#references)</sup>

- **Alternative port support** op **Windows 11 24H2** en **Windows Server 2025**, wat aan users blootgestel word met `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, waar veelvuldige authenticated sessions dieselfde TCP-verbinding kan gebruik

Dit beteken dat ’n low-privileged user eers ’n TCP-verbinding vanaf die SMB client na ’n attacker SMB server op ’n high port kan skep, en dan ’n privileged service kan dwing om toegang tot die **exact same UNC path** te verkry. Indien Windows besluit om die bestaande TCP-verbinding te hergebruik, word die privileged NTLM exchange oor die attacker-controlled transport gestuur en kan dit na die local SMB server gerelay word.<sup>[[1]](#references)</sup>

## Voorwaardes

- Target supports SMB alternative ports:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** of later
- **Windows Server 2025** of later
- Die aanvaller kan ’n local of remote SMB server op ’n gekose high port laat loop
- Die aanvaller kan ’n privileged service dwing om toegang tot ’n UNC path te verkry
- Die privileged authentication moet **NTLM local authentication** wees
- Die target moet relayable wees:<sup>[[1]](#references)</sup>
- Synacktiv het gerapporteer dat dit by verstek op **Windows Server 2025** gewerk het
- Hulle chain het nie op **Windows 11 24H2** gewerk nie omdat outbound SMB signing daar by verstek afgedwing word

## Userland en internals

Vanaf die command line lyk die funksie eenvoudig:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically gebruik die client `WNetAddConnection4W` met undocumented `lpUseOptions`-data. Die relevante opsie is `TraP` (transport parameters), wat uiteindelik deur ’n FSCTL die kernel SMB client bereik en deur `mrxsmb` geparse word.<sup>[[1]](#references)[[3]](#references)</sup>

Belangrike praktiese notas:<sup>[[1]](#references)</sup>

- **UNC-sintaksis het steeds geen port-veld nie**
- **`net use` is per logon-session**
- Die bypass werk steeds omdat **die TCP-connection en die SMB-session aparte objects is**
- Hergebruik van **dieselfde share path** is verpligtend as die exploit daarvan afhang dat die SMB client die voorheen geskepte TCP-connection hergebruik

## Exploitation-vloei

### 1. Skep die aanvaller-beheerde SMB-transport

Begin ’n SMB server op ’n high port en laat Windows daaraan connect:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Die server kan enige credential-paar aanvaar wat jy beheer, byvoorbeeld `user:user`. Die doel van hierdie stap is nog nie privilege escalation nie, maar slegs om die Windows SMB client ’n herbruikbare TCP connection na jou listener te laat oopmaak en behou.<sup>[[1]](#references)</sup>

### 2. Coerce ’n privileged service na dieselfde UNC path

Gebruik ’n coercion primitive soos **PetitPotam** teen dieselfde `\\192.168.56.3\share` path. As die coerced client privileged is en die target name local is (`localhost` of ’n local IP/host), voer Windows **NTLM local authentication** uit.

Omdat die TCP connection hergebruik word, beweeg daardie privileged NTLM exchange na die attacker SMB service in plaas daarvan om direk na die werklike local SMB server te gaan.<sup>[[1]](#references)</sup>

### 3. Relay die privileged authentication terug na local SMB

Die attacker-controlled SMB service stuur die privileged NTLM exchange aan na `ntlmrelayx.py`, wat dit na die masjien se werklike SMB listener relay en ’n session as `NT AUTHORITY\SYSTEM` verkry.<sup>[[1]](#references)</sup>

Tipiese tooling uit die public writeup:<sup>[[1]](#references)</sup>

- `smbserver.py` op ’n custom port om die privileged auth oor die hergebruikte TCP connection te ontvang
- `ntlmrelayx.py` om die captured NTLM na local SMB te relay
- `PetitPotam.exe` of ’n ander coercion primitive om die privileged authentication af te dwing

## Operator notes

- Dit is ’n **local privilege escalation** technique, nie ’n generiese remote relay trick nie<sup>[[1]](#references)</sup>
- Die attacker-controlled SMB service moet die privileged authentication op dieselfde TCP connection hanteer wat oorspronklik vir die share mount gebruik is<sup>[[1]](#references)</sup>
- As die coerced access ’n **ander share path** bereik, kan Windows ’n ander connection establish en breek die chain<sup>[[1]](#references)</sup>
- SMB signing requirements kan die relay laat misluk, selfs wanneer die arbitrary-port step werk<sup>[[1]](#references)</sup>
- As jy slegs Kerberos material het of nie local NTLM kan force nie, is hierdie presiese variant nie voldoende nie<sup>[[1]](#references)</sup>

## Detection and hardening

- Patch **CVE-2026-24294** vanaf **March 2026 Patch Tuesday**<sup>[[4]](#references)</sup>
- Monitor vir `net use` of `New-SmbMapping` wat **non-default SMB ports** gebruik<sup>[[1]](#references)</sup>
- Genereer ’n alert vir ongewone outbound SMB vanaf workstations of servers na **high TCP ports**<sup>[[1]](#references)</sup>
- Hersien coercion opportunities soos **EFSRPC / PetitPotam-style** triggers<sup>[[1]](#references)</sup>
- Enforce SMB signing waar moontlik; Synacktiv merk spesifiek op dat dit hul relay op Windows 11 24H2 geblokkeer het<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
